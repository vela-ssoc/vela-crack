# 暴力破解
crack暴力破解模块

## 方法集合

- [vela.crack](#配置服务)


## 配置服务 
可以启动一个爆破组件
- [crack = vela.crack(config)](#启动服务)

### 服务方法
- [crack.task(url)](#新建任务)
- [crack.start()](#)

```lua
    local crack = vela.crack{}
    crack.start()

    local task = crack.task("https://httpbin.org")
    task.raw[[
        POST / HTTP/1.1
        Host: www.baidu.com
        
        login=§name§&password=§123456§]]
    
    task.mode("cluster_bomb")
    task.payload("admin" , "root" , "system")
    task.Payload("a.txt")
    task.pipe(function(meta)
        vela.Debug("%v" , meta)
    end)
    task.intruder()
```

## 新建任务
crack中启动的任务 

方法: task = crack.task(url)

参数: scheme://address:port  支持: http,https,mysql

内置方法:

- [task.payload(v...)](#taskpayload)
- [task.Payload(file)](#taskPayload)
- [task.u(v...)](#tasku)
- [task.U(file)](#taskU)
- [task.p(v...)](#taskp)
- [task.P(file)](#taskP)
- [task.pipe(function(meta))](#taskpipe)
- [task.case(cnd,...).pipe()](#taskcase)
- [task.mode(str)](#taskmode)
- [task.intruder()](#taskintruder)
- [task.raw(string)](#taskraw)
- [task.thread(int)](#taskthread)
- [task.once(bool)](#taskonce)
- [task.attack()](#taskattack)
- [task.encode(pipe.chains)](#taskencode)

### task.payload
设置payload信息(小写); 这个payload只适用于http 和 https 服务 
```lua
    local crack = vela.crack{}
    local task = crack.task("http://127.0.0.1:8080")
    task.raw[[""]]
    -- 设置第一个字典位置 为: {"admin" , "root" , "system"}
    task.payload("admin" , "root" , "system") 
```

### task.Payload
设置payload文件(大写);按行读取 
```lua
    -- 设置第一个字典位置 按行读取文件 
    task.Payload("a.txt") 
```

### task.u
设置用户名(小写)
```lua
    task.u("admin" , "root")
```

### task.U
设置用户名(大写)
```lua
    task.U("u.txt")
```
### task.p
设置密码信息(小写)
```lua
    task.p("admin" , "root")
```

### task.P
设置密码字典(大写)
```lua
    task.P("p.txt")
```

### task.pipe
处理每个请求的信息 ,满足语法
```lua
    task.pipe(function(meta)
        -- todo 
    end)
```

### task.case
为了加快匹配逻辑 可以直接利用cond条件 底层过滤
```lua
   task.case("stat = ok" , "r_code = 200").pipe(function(meta) 
    print(meta)
    print(meta.response.code)
    print(meta.r_code) --等价 meta.response.code
    print(meta.r_h_content_length) --等价 meta.response.content_length
   end)
```

### task.mode
爆破模式 主要是http服务
```lua
    task.mode("sniper")
    task.mode("pitch_fork")
    task.mode("cluster_bomb")
```

### task.raw
设置http流量原始报文 ,占位分割符号为§
```lua
    local task = crack.task("http://127.0.0.1:8080")
    task.raw[[
    POST /api  HTTP/1.1
    Host: www.baidu.com
    
    name=§root§&pwd=§123456§]]
```

### task.thread
设置爆破线程数量
```lua
    local task = crack.task("http://127.0.0.1:8080")
    task.raw[[
    POST /api  HTTP/1.1
    Host: www.baidu.com
    
    name=§root§&pwd=§123456§]]
    task.thread(100)
```

### task.once
爆破成功结束
```lua
    local task = crack.task("http://127.0.0.1:8080")
    task.once(true)
```

### task.attack
非web应用的爆破方法
```lua
    local task = crack.task("http://127.0.0.1:8080")
    task.once(true)
    task.attack()
```

### task.encode
设置加密过程
```lua
    local md5 = vela.crypto.md5
    local sha1 = vela.crypto.sha1

    local task = crack.task("http://127.0.0.1:8080")
    
    task.encode(function(meta)
        local payload = meta.payload
        meta.set_payload(0 , md5(payload[1]))
        meta.set_payload(0 , sha1(payload[1]))
        meta.encode_md5("payload" , 0)
        meta.encode_bs64("payload" , 0)
    end)

```

## metadata
内部传输数据结构 存储了运行过程中的所有数据

内部变量:
- [metadata.response](#metadata) 
- [metadata.request](#metadata)
- [metadata.error](#metadata)
- [metadata.state](#metadata)
- [metadata.payload](#metadata)
- [metadata.port](#metadata)
- [metadata.scheme](#metadata)
- [metadata.host](#metadata)
- [metadata.banner](#metadata)

内部方法:
- [metadata.encode_md5(name , [index])](#metadata)
- [metadata.encode_bs64(name , [index])](#metadata)
- [metadata.encode_url(name , [index])](#metadata)
- [metadata.risk(subject)](#metadata)
- [metadata.happy()](#metadata)

修改变量:
- [metadata.username](#metadata)
- [metadata.password](#metadata)

```lua
    task.pipe(function(metadata)
        print(metadata.response)
        print(metadata.request)
        print(metadata.error)
        print(metadata.state)
        print(metadata.payload)
        print(metadata.port)
        print(metadata.scheme)
        print(metadata.host)
        print(metadata.banner)
        
        metadata.encode_md5("username")
        metadata.encode_md5("payload" , 0)
    
        local ev = metadata.risk("高危")
        ev.subject = "发现弱口令"
        -- todo risk ev api
    
        metadata.username = "admin"
        metadata.password = "123456"
        
        metadata.set_payload(0 , "admin") -- 设置第一个值为admin
        metadata.set_payload(1 , "123456") -- 设置第一个值为123456
    end)
```