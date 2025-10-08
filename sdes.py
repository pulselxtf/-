class S_DES:
    """
    简化数据加密标准（S-DES）的核心实现
    遵循重庆大学信息安全导论课程中的算法定义，支持8位二进制明/密文加解密，使用10位密钥
    """

    # 置换表定义（严格遵循课程PPT规范）
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # 密钥初始置换表
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # 子密钥生成置换表
    IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始置换表
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]  # 逆初始置换表
    EP_BOX = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展置换表（4位→8位）
    SP_BOX = [2, 4, 3, 1]  # P盒置换表（4位）

    # S盒定义（课程指定的替换规则）
    S_BOX1 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]
    S_BOX2 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]

    def __init__(self, key):
        """
        初始化S-DES实例，生成子密钥K1和K2
        :param key: 10位二进制字符串（如"1010000010"）
        """
        self.key = self._str_to_bits(key)
        if len(self.key) != 10:
            raise ValueError("密钥必须是10位二进制字符串")
        self.subkeys = self._generate_subkeys()  # 生成K1和K2

    def _str_to_bits(self, bit_str):
        """
        将二进制字符串转换为位数组
        :param bit_str: 二进制字符串（如"1010"）
        :return: 对应的位数组（如[1,0,1,0]）
        """
        return [int(bit) for bit in bit_str if bit in ('0', '1')]

    def _bits_to_str(self, bits):
        """
        将位数组转换为二进制字符串
        :param bits: 位数组（如[1,0,1,0]）
        :return: 对应的二进制字符串（如"1010"）
        """
        return ''.join(str(bit) for bit in bits)

    def _permute(self, bits, perm_table):
        """
        根据置换表对位序列进行重排
        :param bits: 原始位数组
        :param perm_table: 置换表（元素为1-based索引）
        :return: 置换后的位数组
        """
        return [bits[i - 1] for i in perm_table]

    def _left_shift(self, bits, shift_count):
        """
        对位数组进行循环左移
        :param bits: 原始位数组
        :param shift_count: 左移位数
        :return: 左移后的位数组
        """
        return bits[shift_count:] + bits[:shift_count]

    def _xor(self, bits1, bits2):
        """
        对两个位数组进行按位异或操作
        :param bits1: 第一个位数组
        :param bits2: 第二个位数组（长度需与bits1一致）
        :return: 异或结果位数组
        """
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def _s_box_substitute(self, bits, s_box):
        """
        S盒替换（4位输入→2位输出）
        :param bits: 4位输入位数组
        :param s_box: 对应的S盒（4x4矩阵）
        :return: 2位输出位数组
        """
        row = bits[0] * 2 + bits[3]  # 行索引：第1位和第4位组成
        col = bits[1] * 2 + bits[2]  # 列索引：第2位和第3位组成
        value = s_box[row][col]
        return [(value >> 1) & 1, value & 1]  # 转换为2位二进制

    def _generate_subkeys(self):
        """
        生成子密钥K1和K2
        流程：P10置换→分块左移→P8置换
        :return: 包含K1和K2的元组（均为8位位数组）
        """
        # 1. 对10位密钥进行P10置换
        p10_result = self._permute(self.key, self.P10)
        left, right = p10_result[:5], p10_result[5:]  # 分为左右各5位

        # 2. 左移1位后生成K1
        left1 = self._left_shift(left, 1)
        right1 = self._left_shift(right, 1)
        k1 = self._permute(left1 + right1, self.P8)

        # 3. 再左移2位后生成K2
        left2 = self._left_shift(left1, 2)
        right2 = self._left_shift(right1, 2)
        k2 = self._permute(left2 + right2, self.P8)

        return (k1, k2)

    def _feistel_function(self, right, subkey):
        """
        Feistel轮函数（S-DES核心变换）
        流程：扩展置换→与子密钥异或→S盒替换→P盒置换
        :param right: 右半部分4位位数组
        :param subkey: 8位子密钥位数组
        :return: 4位变换结果
        """
        # 扩展置换：4位→8位
        expanded = self._permute(right, self.EP_BOX)
        # 与子密钥异或
        xored = self._xor(expanded, subkey)
        # S盒替换：8位→4位（前4位用S1，后4位用S2）
        s1_out = self._s_box_substitute(xored[:4], self.S_BOX1)
        s2_out = self._s_box_substitute(xored[4:], self.S_BOX2)
        # P盒置换：4位→4位
        return self._permute(s1_out + s2_out, self.SP_BOX)

    def encrypt(self, plaintext):
        """
        加密8位二进制明文
        :param plaintext: 8位二进制字符串（如"00000000"）
        :return: 8位二进制密文字符串
        """
        plain_bits = self._str_to_bits(plaintext)
        if len(plain_bits) != 8:
            raise ValueError("明文必须是8位二进制字符串")

        # 初始置换IP
        ip_result = self._permute(plain_bits, self.IP)
        left, right = ip_result[:4], ip_result[4:]  # 分为左右各4位

        # 第一轮Feistel变换（使用K1）
        f_result = self._feistel_function(right, self.subkeys[0])
        new_left = self._xor(left, f_result)
        left, right = right, new_left  # 交换

        # 第二轮Feistel变换（使用K2）
        f_result = self._feistel_function(right, self.subkeys[1])
        new_left = self._xor(left, f_result)

        # 逆初始置换IP_INV，得到密文
        cipher_bits = self._permute(new_left + right, self.IP_INV)
        return self._bits_to_str(cipher_bits)

    def decrypt(self, ciphertext):
        """
        解密密文（与加密流程相同，但子密钥顺序相反）
        :param ciphertext: 8位二进制密文字符串
        :return: 8位二进制明文字符串
        """
        cipher_bits = self._str_to_bits(ciphertext)
        if len(cipher_bits) != 8:
            raise ValueError("密文必须是8位二进制字符串")

        # 初始置换IP
        ip_result = self._permute(cipher_bits, self.IP)
        left, right = ip_result[:4], ip_result[4:]  # 分为左右各4位

        # 第一轮Feistel变换（使用K2，解密子密钥顺序相反）
        f_result = self._feistel_function(right, self.subkeys[1])
        new_left = self._xor(left, f_result)
        left, right = right, new_left  # 交换

        # 第二轮Feistel变换（使用K1）
        f_result = self._feistel_function(right, self.subkeys[0])
        new_left = self._xor(left, f_result)

        # 逆初始置换IP_INV，得到明文
        plain_bits = self._permute(new_left + right, self.IP_INV)
        return self._bits_to_str(plain_bits)

    def encrypt_ascii(self, text):
        """
        加密ASCII字符串（自动转换为8位二进制后分块加密）
        :param text: 待加密的ASCII字符串（如"Hello"）
        :return: 加密后的二进制字符串（每8位对应一个字符）
        """
        cipher_bin = []
        for char in text:
            # 将字符转换为8位二进制
            char_bin = format(ord(char), '08b')
            # 加密并添加到结果
            cipher_bin.append(self.encrypt(char_bin))
        return ''.join(cipher_bin)

    def decrypt_ascii(self, cipher_bin):
        """
        解密ASCII字符串的二进制密文（分块解密后转换为字符）
        :param cipher_bin: 加密后的二进制字符串
        :return: 解密后的ASCII字符串
        """
        if len(cipher_bin) % 8 != 0:
            raise ValueError("密文长度必须是8的倍数")

        plaintext = []
        # 每8位为一个块解密
        for i in range(0, len(cipher_bin), 8):
            block = cipher_bin[i:i + 8]
            plain_bin = self.decrypt(block)
            # 转换为字符
            plaintext.append(chr(int(plain_bin, 2)))
        return ''.join(plaintext)
