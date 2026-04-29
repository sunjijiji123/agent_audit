# DAS-DS 规范对比分析

## 当前实现 vs 规范要求

### 1. processCreate (rawLogNum: 110001)

**规范要求字段：**
```json
{
  "eventType": "processCreate",     ✓ 已实现
  "rawLogNum": 110001,               ✓ 已实现
  "logType": "process",              ✓ 已实现（已修复）
  "opType": "create",                ✓ 已实现
  "localTime": "2025-12-23 10:51:12", ✓ 已实现（YYYY-MM-DD HH:MM:SS格式）
  "unixTime": 1766458272,            ✓ 已实现
  "logfuzId": "",                    ✓ 已实现（空字符串，计算 deferred）

  // 进程信息
  "processId": "29354",              ✓ 已实现
  "image": "/usr/bin/ls",            ✓ 已实现
  "commandLine": "ls --color=auto",  ✓ 已实现
  "processUserName": "root",         ✓ 已实现
  "processMd5": "",                  ✓ 已实现（空字符串，计算 deferred）
  "processName": "ls",               ✓ 已实现
  "processStartTime": "...",         ❌ 缺失
  "processGuid": "",                 ✓ 已实现（空字符串，待实现）

  // 父进程信息
  "parentProcessName": "bash",       ✓ 已实现（从chain）
  "parentProcessGuid": "",           ✓ 已实现（空字符串）
  "parentProcessId": "26210",        ✓ 已实现
  "parentImage": "/usr/bin/bash",    ❌ 缺失
  "parentCommandLine": "-bash ",     ❌ 缺失
  "parentProcessUserName": "root",   ❌ 缺失
  "parentProcessMd5": "",            ✓ 已实现（空字符串）
  "parentProcessStartTime": "...",   ❌ 缺失

  // 终端/登录信息
  "relateAddress": "10.11.47.239",   ❌ 缺失（SSH客户端IP）
  "loginId": "230597",               ❌ 缺失（登录会话ID）
  "traceId": "",                     ✓ 已实现（空字符串）
  "initialProcess": "0",             ❌ 缺失
  "destUserId": "0",                 ❌ 缺失
  "currentDirectory": "",            ✓ 已删除（不在 DAS-DS 规范中）
  "teletype": "pts4",                ❌ 缺失
}
```

**改进建议：**
1. ✓ `logType` 已改为 `"process"`
2. ✓ `localTime` 格式已修复为 `"YYYY-MM-DD HH:MM:SS"`
3. ✓ `logfuzId` 已置空（计算 deferred）
4. ✓ `processMd5` 已置空（计算 deferred）
5. ✓ `currentDirectory` 已删除（不在规范中）
6. 添加 `processStartTime`（进程启动时间，从agent_tree的fork_time）
7. 添加父进程完整信息（从/proc/{ppid}读取）
8. 添加终端信息（relateAddress从SSH会话，loginId从utmp，teletype从tty）

---

### 2. fileEvent (rawLogNum: 120003)

**规范要求字段：**
```json
{
  "eventType": "fileEvent",          ✓ 已实现
  "rawLogNum": 120003,               ✓ 已实现
  "logType": "file",                 ✓ 已实现（已修复）
  "opType": "write",                 ✓ 已实现

  // 进程信息（同processCreate）
  ...                                ✓/❌ 同上

  // 文件信息
  "filePath": "/root/script.py",     ✓ 已实现（已过滤目录）
  "fileName": "11111111.sh",         ❌ 缺失（文件名部分）
  "fileMd5": "",                     ✓ 已实现（空字符串，计算 deferred）
  "fileSize": 1024,                  ✓ 已实现（仅 open 事件）
  "fileType": "",                    ✓ 已实现（仅 open 事件，ELF检测）
  "createTime": "",                  ✓ 已实现（空字符串，Linux不支持）
  "modifyTime": "2025-12-23 10:57:29", ✓ 已实现（仅 open 事件）
  "targetFilename": "",              ✓ 已实现（空字符串，deferred）
}
```

**当前实现差异：**
- 有 `fileFd`, `fileBytes`（规范无）
- 有 `processChain`（规范无）

**改进建议：**
1. `logType` 改为 `"file"`
2. 添加 `fileName`（从filePath提取basename）
3. 添加 `targetFilename`（完整路径）
4. 添加文件元数据（fileMd5计算、fileSize/fileType检测）
5. 添加 modifyTime（从stat获取）

---

### 3. networkConnect (rawLogNum: 130001/130002)

**规范要求字段：**
```json
{
  "eventType": "networkConnect",     ✓ 已实现
  "rawLogNum": 130001,               ✓ 已实现
  "logType": "network",              ❌ 当前："agent-audit"
  "opType": "connect",               ✓ 已实现

  // 进程信息（同processCreate）
  ...                                ✓/❌ 同上

  // 网络信息
  "transProtocol": "TCP",            ❌ 缺失
  "srcAddress": "192.168.27.254",    ❌ 缺失
  "srcPort": 45794,                  ❌ 缺失
  "destAddress": "192.168.27.242",   ❌ 缺失
  "destPort": 22,                    ❌ 缺失
  "initiated": "true",               ❌ 缺失（出站/入站）
}
```

**当前实现：**
- `networkDst: "family=1 (raw)"` — 格式不匹配（应为IP:Port）

**改进建议：**
1. `logType` 改为 `"network"`
2. 解析BPF的sockaddr结构体，提取IP/Port
3. 添加 `srcAddress`/`srcPort`（本机地址）
4. 添加 `transProtocol`（TCP/UDP）
5. 添加 `initiated`（出站连接为true）

---

### 4. dnsQuery (rawLogNum: 130003)

**规范要求字段：**
```json
{
  "eventType": "dnsQuery",           ✓ 已实现
  "rawLogNum": 130003,               ✓ 已实现
  "logType": "domain",               ❌ 当前："agent-audit"
  "opType": "connect",               ❌ 当前："resolve"

  // 进程信息（同processCreate）
  ...                                ✓/❌ 同上

  // DNS信息
  "requestDomain": "www.baidu.com",  ✓ 已实现（dnsQuery）
  "queryResults": "180.101.49.44..." ❌ 缺失（解析结果）
}
```

**改进建议：**
1. `logType` 改为 `"domain"`
2. `opType` 改为 `"connect"`
3. 字段名：`dnsQuery` → `requestDomain`
4. 添加 `queryResults`（DNS解析结果）

---

### 5. loginEvent (rawLogNum: 150001/150002)

**规范要求字段：**
```json
{
  "eventType": "loginEvent",         ❌ 未实现
  "rawLogNum": 150001,               ❌ 未实现
  "logType": "account",              ❌ 未实现
  "opType": "login",                 ❌ 未实现

  // 网络信息
  "transProtocol": "TCP",            ❌ 未实现
  "srcAddress": "10.23.16.98",       ❌ 未实现
  "srcPort": 49304,                  ❌ 未实现
  "destAddress": "",                 ❌ 未实现
  "destPort": 22,                    ❌ 未实现

  // 登录结果
  "catOutcome": "OK"/"FAIL",         ❌ 未实现
  "failReason": "",                  ❌ 未实现

  // 进程信息
  "processId": "...",                ❌ 未实现
  "image": "/usr/sbin/sshd",         ❌ 未实现
  "appProtocol": "SSH"                ❌ 未实现
}
```

**实现难度：**
- 需要监控SSH认证日志（/var/log/auth.log）
- 或通过auditd子系统监控登录事件
- 需要解析SSH会话信息

**建议：** 暂不实现（不在eBPF能力范围内）

---

## 关键改进项（优先级）

### 高优先级（必须修复） — 已完成 ✓

1. ✓ **logType 修正**
   - processCreate: `"agent-audit"` → `"process"` ✓
   - fileEvent: `"agent-audit"` → `"file"` ✓
   - networkConnect: `"agent-audit"` → `"network"` ✓
   - dnsQuery: `"agent-audit"` → `"domain"` ✓

2. ✓ **localTime 格式修复**
   - 当前：ISO8601+timezone `"2026-04-29T13:39:54+08:00"`
   - 规范：`"YYYY-MM-DD HH:MM:SS"` `"2025-12-23 10:57:29"` ✓
   - 已使用 strftime 格式化

3. ✓ **filePath 过滤目录**
   - 当前：包含目录路径 `"/usr/share/locale/..."` 
   - 规范：仅文件路径 ✓
   - 已使用 os.path.isfile() 过滤

4. ✓ **logfuzId 置空**
   - 当前：生成 MD5 去重 ID
   - 规范：空字符串 `""` ✓
   - 已删除生成逻辑

5. ✓ **processMd5 置空**
   - 当前：实时计算（进程退出时为空）
   - 规范：空字符串（计算 deferred） ✓
   - 已删除计算逻辑

6. ✓ **currentDirectory 删除**
   - 当前：输出 `proc_info["cwd"]`
   - 规范：不在规范中 ✓
   - 已删除字段

7. ✓ **文件元数据添加**
   - fileSize/fileType/modifyTime ✓
   - 仅 FILE open 事件（read/write 跳过） ✓
   - fileMd5/createTime/targetFilename 空字符串（deferred） ✓

### 中优先级（建议添加）

5. **父进程完整信息**
   - parentImage, parentCommandLine, parentProcessUserName, parentProcessMd5
   - 从 `/proc/{ppid}/` 读取

6. **网络连接详细字段**
   - transProtocol (TCP/UDP)
   - srcAddress, srcPort（本机地址）
   - destAddress, destPort（目标地址）
   - initiated (true/false)

7. **文件元数据**
   - fileName (basename)
   - targetFilename (完整路径)
   - fileSize, fileType (ELF检测)

8. **DNS解析结果**
   - queryResults (解析后的IP列表)

### 低优先级（可选）

9. **终端/登录信息**
   - relateAddress (SSH客户端IP)
   - loginId (登录会话ID)
   - teletype (pts/tty)
   - initialProcess, destUserId

10. **时间字段**
   - processStartTime (进程启动时间)
   - modifyTime (文件修改时间)

---

## 无法实现的字段

- **loginEvent** — 需要监控SSH认证日志，不在eBPF syscall监控范围
- **createTime** — 文件创建时间在Linux中难以获取（ext4不保存）
- **fileMd5/fileSize** — write事件时文件可能未关闭，无法立即计算
- **relateAddress/loginId** — 需要解析SSH会话、utmp数据库

---

## 实现建议

### 第一阶段（必做）

修改 `daemon.py` 的 `_build_single_event_log()`：

```python
# 1. logType 修正
log_type_map = {
    "processCreate": "process",
    "fileEvent": "file",
    "networkConnect": "network",
    "dnsQuery": "domain",
}
log_entry["logType"] = log_type_map.get(event_type, "agent-audit")

# 2. dnsQuery opType 修正
if event_type == "dnsQuery":
    log_entry["opType"] = "connect"
    log_entry["requestDomain"] = log_entry.pop("dnsQuery")

# 3. networkDst 解析（从BPF sockaddr）
if event_type == "networkConnect":
    # 解析 "AF_INET 192.168.5.1:80" 格式
    # 提取 destAddress, destPort
```

### 第二阶段（建议）

添加父进程信息采集：

```python
# 从 /proc/{ppid}/ 读取父进程完整信息
if parent_pid:
    parent_proc = _get_proc_info(parent_pid)
    log_entry["parentImage"] = parent_proc["exe"]
    log_entry["parentCommandLine"] = parent_proc["cmdline"]
    log_entry["parentProcessUserName"] = parent_proc["username"]
    log_entry["parentProcessMd5"] = _compute_md5(parent_proc["exe"])
```

### 第三阶段（可选）

添加网络详细字段、DNS解析结果、文件元数据等。