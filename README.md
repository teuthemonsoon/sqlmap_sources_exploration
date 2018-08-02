# Sqlmap源码分析-布尔盲注逻辑解析

web自动化扫描技术常常是安全的老生常谈，sql注入自动化扫描自然是其中的重点，而sql布尔类型盲注更是sql注入自动化检测让人头疼的东西。被奉为安全界神器的sqlmap就具有高度的自动化检测能力，它究竟有何奥秘，今晚我们一起~~走近科学~~ ~~扒一扒sqlmap的皮~~ 跟随着sqlmap的步伐，探讨sqlmap是如何检测布尔类型盲注以及它可能出现的弊端吧。



我采用的web漏洞环境是sqli-lab的lesson-1，但**去掉了sql语句与sql报错回显**

`python sqlmap.py -u "http://localhost/sqli-labs/sqli-labs/Less-1/?id=2" --technique B`

首先直接从`sqlmap.py`跟进查看`controller.py`的`start`函数，在一大堆初始化、读取配置、检查waf、检查连接等操作后，看到令人心动的函数：

```python
elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.tech or conf.skipStatic:
    check = checkDynParam(place, parameter, value)
```

checkDynParam跟进一下

```python
randInt = randomInt()
infoMsg = "testing if %s parameter '%s' is dynamic" % (paramType, parameter)
logger.info(infoMsg)

try:
    payload = agent.payload(place, parameter, value, getUnicode(randInt))
    dynResult = Request.queryPage(payload, place, raise404=False)

    if not dynResult:
        infoMsg = "confirming that %s parameter '%s' is dynamic" % (paramType, parameter)
        logger.info(infoMsg)

        randInt = randomInt()
        payload = agent.payload(place, parameter, value, getUnicode(randInt))
        dynResult = Request.queryPage(payload, place, raise404=False)
result = None if dynResult is None else not dynResult
kb.dynamicParameter = result
```

**Request.queryPage**函数很关键，sqlmap中常常会用到这个函数进行页面请求，但除此之外，它还有别的关键用处：大概来说，即是将此payload的返回页面与初始页面内容`kb.originalPage`（本例指http://localhost/sqli-labs/sqli-labs/Less-1/?id=2）对比，得出相似性，若高度相似则Request.queryPage返回True，反之返回False。

其算法大概为：使用seqMatcher设置初始页面内容为序列1，此次页面内容为序列2，将从两个序列的第一个不同的字符开始到各页面结束处的两个字符串重新赋值为序列1、序列2，后利用`seqMatcher.quick_ratio()`方法得出相似性，再比对区间(0.02,0.98)进行判定。代码太长，各位客官有兴趣可在sqlmap/lib/request/comparison.py阅读。

这个时候再看CheckDynParam函数：第一次将发送payload:?id=四位数randomInt对比kb.originalPage值得到相似度，若页面返回结果一样则dybResult=false，认为页面不是动态的。否则重新生成ramdonInt再进行一次上述过程。（看代码很好懂）

CheckDynParam函数用来确认指定的参数值是否会动态影响页面返回。在下面的代码可以看出如果设置了--skip-static则会跳过CheckDynParam函数认为是false的url参数。当然了，在本例中返回True。

往下走可以看到另一个让人心动的函数`heuristicCheckSqlInjection(place, parameter)`

来看看heuristicCheckSqlInjection(启发式sql注入)的核心代码：

```python
    def _(page):
        return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)

    casting = _(page) and not _(kb.originalPage)

    if not casting and not result and kb.dynamicParameter and origValue.isdigit():
        randInt = int(randomInt())
        payload = "%s%s%s" % (prefix, "%d-%d" % (int(origValue) + randInt, randInt), suffix)
        payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
        result = Request.queryPage(payload, place, raise404=False)

        if not result:
            randStr = randomStr()
            payload = "%s%s%s" % (prefix, "%s%s" % (origValue, randStr), suffix)
            payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
            casting = Request.queryPage(payload, place, raise404=False)

    kb.heuristicTest = HEURISTIC_TEST.CASTED if casting else HEURISTIC_TEST.NEGATIVE if not result else HEURISTIC_TEST.POSITIVE

    if casting:
        errMsg = "possible %s casting " % ("integer" if origValue.isdigit() else "type")
        errMsg += "detected (e.g. \"$%s=intval($_REQUEST['%s'])\") " % (parameter, parameter)
        errMsg += "at the back-end web application"
        logger.error(errMsg)

        if kb.ignoreCasted is None:
            message = "do you want to skip those kind of cases (and save scanning time)? %s " % ("[Y/n]" if conf.multipleTargets else "[y/N]")
            kb.ignoreCasted = readInput(message, default='Y' if conf.multipleTargets else 'N').upper() != 'N'

    elif result:
        infoMsg += "be injectable"
        if Backend.getErrorParsedDBMSes():
            infoMsg += " (possible DBMS: '%s')" % Format.getErrorParsedDBMSes()
        logger.info(infoMsg)

    else:
        infoMsg += "not be injectable"
        logger.warn(infoMsg)
```

启发式sql注入在这段代码前首先会生成一段长度为10的由单引号双引号反斜杠左右括号和点随机生成的字符串randomStr，然后以id=randomStr发送payload，然后：

(1)检查返回页面中是否有DBMS错误，赋值给result变量			  (2)_(page)函数检查返回页面中是否有`('Type mismatch', 'Error converting', 'Failed to convert','System.FormatException','java.lang.NumberFormatException', 'ValueError: invalid literal')`字符串(程序没有try-catch，期望得到数字而没有预测到字符串情况)，若有，heuristicCheckSqlInjection返回true

若满足not casting and not result and kb.dynamicParameter and origValue.isdigit()：
使用Request.queryPage发送id=randomInt-(比randomInt小2的数)，比较response和kb.originalPage，若高度相似则认为可能有注入
若无，则Request.queryPage发送id=origValue+randomStr 此处为2MWlg，若与kb.origanalPage高度相似，认为程序可能用了`intval($_REQUEST['id']))` ，询问sqlmap用户：

```
[15:34:36] [ERROR] possible integer casting detected (e.g. "$id=intval($_REQUEST['id'])") at the back-end web application
do you want to skip those kind of cases (and save scanning time)? [y/N] 
```

这里就出现问题了：

sqli-lab的语句是：

```sql
SELECT * FROM users WHERE id='$id' LIMIT 0,1
```

而在mysql中select * from users where id='2whatever'实际上返回结果等于select * from users where id= '2'。

程序本没有intval操作，sqlmap却认为有，根本原因是sqlmap认为id=2的页面其sql语言应该是SELECT * FROM users WHERE id=$id LIMIT 0,1（没有单引号）。如果在sqlmap的问询中回答了y或开启了--smart选项，恭喜你完美错过了漏洞。

heuristicCheckSqlInjection逻辑大概如此，其返回heuristicCheckSqlInjection认为有无sql注入，有：true，无：false。当然这个结果无论如何都会继续往下走，除非在sqlmap的问询中回答了y或开启了--smart选项。

紧接着是第三个心动函数：`checkSqlInjection(place, parameter, value)`，这是sqlmap最核心的检测sql注入函数。

函数前部分加载了两个payload，一个是tests，一个是conf.boundaries。tests中存放了各种类型注入、各式数据库、各种适用语句位置以及level的payload，conf.boundaries则存放各种情况下的加在payload前后的prefix、suffix。接着sqlmap把合适的payload和boundaries组合在一起。

tests的第一组数据:{'risk': 1, 'title': 'AND boolean-based blind - WHERE or HAVING clause', 'clause': [1], 'level': 1, 'request': {'payload': 'AND [RANDNUM]=[RANDNUM]'}, 'vector': 'AND [INFERENCE]', 'where': [1], 'response': {'comparison': 'AND [RANDNUM]=[RANDNUM1]'}, 'stype': 1}

boundaries符合level=1的第一组数据：{'suffix': ' AND ([RANDNUM]=[RANDNUM]', 'level': 1, 'clause': [1], 'ptype': 1, 'prefix': ')', 'where': [1, 2]}

**sqlmap第一次发送的payload即从上面组合而来**。

这里如果给sqlmap指定了--suffix或--prefix参数，则具有优先权，sqlmap将不再使用boundaries里的数据。

sqlmap判断布尔类型盲注有两个逻辑：

```python
     if method == PAYLOAD.METHOD.COMPARISON:
                            # Generate payload used for comparison
                            def genCmpPayload():
                                sndPayload = agent.cleanupPayload(test.response.comparison, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) else None)

                                # Forge response payload by prepending with
                                # boundary's prefix and appending the boundary's
                                # suffix to the test's ' <payload><comment> '
                                # string
                                boundPayload = agent.prefixQuery(sndPayload, prefix, where, clause)
                                boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                cmpPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                                return cmpPayload

                            # Useful to set kb.matchRatio at first based on
                            # the False response content
                            kb.matchRatio = None
                            kb.negativeLogic = (where == PAYLOAD.WHERE.NEGATIVE)
                            Request.queryPage(genCmpPayload(), place, raise404=False)
                            falsePage = threadData.lastComparisonPage or ""

                            # Perform the test's True request
                            trueResult = Request.queryPage(reqPayload, place, raise404=False)
                            truePage = threadData.lastComparisonPage or ""

                            if trueResult and not(truePage == falsePage and not kb.nullConnection):
                                falseResult = Request.queryPage(genCmpPayload(), place, raise404=False)

                                # Perform the test's False request
                                if not falseResult:
                                    infoMsg = "%s parameter '%s' seems to be '%s' injectable " % (paramType, parameter, title)
                                    logger.info(infoMsg)

```
 truePage:`id=2) AND 8831=8831 AND (4240=4240`返回页面

falsePage:`id=2) AND 4723=1575 AND (7430=7430`返回页面

第一个逻辑：在不考虑空连接(指定参数--null-connection)的情况下，若`id=2`的返回值和truePage高度相似，且truePage与falsePage 不是完全相等，则再进行`id=2`和`id=2) [randomInt1]=[randomInt1] AND ([randomInt2]=[randomInt3]`的比较来判断是否存在布尔类型注入（代码讲得更清楚）

```python
if not injectable and not any((conf.string, conf.notString, conf.regexp)) and kb.pageStable:
    trueSet = set(extractTextTagContent(truePage))
    falseSet = set(extractTextTagContent(falsePage))
    candidates = filter(None, (_.strip() if _.strip() in (kb.pageTemplate or "") and _.strip() not in falsePage and _.strip() not in threadData.lastComparisonHeaders else None for _ in (trueSet - falseSet)))

    if candidates:
        conf.string = candidates[0]
        infoMsg = "%s parameter '%s' seems to be '%s' injectable (with --string=\"%s\")" % (paramType, parameter, title, repr(conf.string).lstrip('u').strip("'"))
        logger.info(infoMsg)
```

第二个逻辑：在truepage和falsepage中抽取出html中被文字标签相夹的值

（extractTextTagContent采用的正则：

`r"(?si)<(abbr|acronym|b|blockquote|br|center|cite|code|dt|em|font|h\d|i|li|p|pre|q|strong|sub|sup|td|th|title|tt|u)(?!\w).*?>(?P<result>[^<]+)"`

效果：				

`>>> extractTextTagContent(u'<html><head><title>Title</title></head><body><pre>foobar</pre><a href="#link">Link</a></body></html>')`
				`返回[u'Title', u'foobar']`）

求差集后检查是否在kb.pageTemplate,falsepage,threadData.lastComparisonHeaders中，从而判断是否存在布尔类型注入。

### sqlmap稍稍不完美的地方：

1.上面提到的sqlmap在heuristicCheckSqlInjection中逻辑较为粗暴，没有考虑id=2整形被单引号包裹的情况，可能会造成漏报。

2.sqlmap的思维似乎停留在web1.0的层面上，像`r"(?si)<(abbr|acronym|b|blockquote|br|center|cite|code|dt|em|font|h\d|i|li|p|pre|q|strong|sub|sup|td|th|title|tt|u)(?!\w).*?>(?P<result>[^<]+)"`这样的正则表达式，可能在web2.0（如采用react框架、angular框架）的网站匹配不到任何结果，也可能布尔类型注入的回显点根本不在这些标签里面，造成漏报。

