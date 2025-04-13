# DParser

一个用于解析特定协议数据的Python解析器。

## 功能

- 从JSON规则文件加载协议定义
- 解析二进制数据为结构化信息
- 支持多种数据类型转换

## 安装

1. 确保已安装Python 3.8+
2. 克隆本仓库
3. 创建虚拟环境:
   ```
   python -m venv .venv
   ```
4. 激活虚拟环境并安装依赖:
   ```
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

## 使用

1. 在rules目录下添加协议规则JSON文件
2. 导入并使用DParser类:
   ```python
   from parser import DParser
   
   parser = DParser()
   result = parser.parse("protocol_name",binary_data)
   ```

## 协议规则格式

参考rules目录下的示例JSON文件。
