import time
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from concurrent.futures import ThreadPoolExecutor


class S_DES:
    # 作业定义的置换表与S盒
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # 密钥初始置换
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # 子密钥置换
    IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始置换
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]  # 最终置换
    EP_BOX = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展置换
    SP_BOX = [2, 4, 3, 1]  # P盒置换
    S_BOX1 = [  # S盒1
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]
    S_BOX2 = [  # S盒2
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]

    def __init__(self, key):
        """初始化：生成子密钥K1、K2"""
        self.key = self._str_to_bits(key)
        assert len(self.key) == 10, "密钥必须是10位二进制字符串"
        self.subkeys = self._generate_subkeys()

    def _str_to_bits(self, s):
        """二进制字符串 → 位数组（如"0101" → [0,1,0,1]）"""
        return [int(bit) for bit in s]

    def _bits_to_str(self, bits):
        """位数组 → 二进制字符串（如[0,1,0,1] → "0101"）"""
        return ''.join(str(bit) for bit in bits)

    def _permute(self, bits, perm_table):
        """按置换表重排位（如IP、P10等）"""
        return [bits[i - 1] for i in perm_table]  # 置换表是1-based，列表是0-based

    def _left_shift(self, bits, shift):
        """循环左移（生成子密钥时用）"""
        return bits[shift:] + bits[:shift]

    def _xor(self, bits1, bits2):
        """按位异或（Feistel变换、密钥混合用）"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def _s_box_sub(self, bits, s_box):
        """S盒替换（4位→2位）：行=第1+4位，列=第2+3位"""
        row = bits[0] * 2 + bits[3]
        col = bits[1] * 2 + bits[2]
        val = s_box[row][col]
        return [(val >> 1) & 1, val & 1]  # 转换为2位二进制

    def _generate_subkeys(self):
        """生成子密钥K1、K2（作业的密钥扩展流程）"""
        # 1. P10置换
        p10 = self._permute(self.key, self.P10)
        left, right = p10[:5], p10[5:]
        # 2. 左移1位 → 生成K1
        left1 = self._left_shift(left, 1)
        right1 = self._left_shift(right, 1)
        k1 = self._permute(left1 + right1, self.P8)
        # 3. 左移2位 → 生成K2
        left2 = self._left_shift(left1, 2)
        right2 = self._left_shift(right1, 2)
        k2 = self._permute(left2 + right2, self.P8)
        return (k1, k2)

    def _f_function(self, right, subkey):
        """Feistel轮函数（扩展、异或、S盒、P盒）"""
        # 扩展置换（4位→8位）
        expanded = self._permute(right, self.EP_BOX)
        # 与子密钥异或
        xored = self._xor(expanded, subkey)
        # S盒替换（8位→4位）
        s1_out = self._s_box_sub(xored[:4], self.S_BOX1)
        s2_out = self._s_box_sub(xored[4:], self.S_BOX2)
        # P盒置换（4位→4位）
        return self._permute(s1_out + s2_out, self.SP_BOX)

    def encrypt(self, plaintext):
        """8位二进制明文 → 加密为8位二进制密文"""
        bits = self._str_to_bits(plaintext)
        assert len(bits) == 8, "明文必须是8位二进制字符串"
        # 初始置换IP
        ip = self._permute(bits, self.IP)
        left, right = ip[:4], ip[4:]
        # 第一轮Feistel（用K1）
        f_out = self._f_function(right, self.subkeys[0])
        new_left = self._xor(left, f_out)
        left, right = right, new_left
        # 第二轮Feistel（用K2）
        f_out = self._f_function(right, self.subkeys[1])
        new_left = self._xor(left, f_out)
        # 最终置换IP⁻¹
        final = self._permute(new_left + right, self.IP_INV)
        return self._bits_to_str(final)

    def decrypt(self, ciphertext):
        """8位二进制密文 → 解密为8位二进制明文"""
        bits = self._str_to_bits(ciphertext)
        assert len(bits) == 8, "密文必须是8位二进制字符串"
        # 初始置换IP
        ip = self._permute(bits, self.IP)
        left, right = ip[:4], ip[4:]
        # 第一轮Feistel（用K2，解密子密钥反序）
        f_out = self._f_function(right, self.subkeys[1])
        new_left = self._xor(left, f_out)
        left, right = right, new_left
        # 第二轮Feistel（用K1）
        f_out = self._f_function(right, self.subkeys[0])
        new_left = self._xor(left, f_out)
        # 最终置换IP⁻¹
        final = self._permute(new_left + right, self.IP_INV)
        return self._bits_to_str(final)

    def encrypt_ascii(self, text):
        """ASCII字符串 → 二进制密文（每个字符转8位二进制后加密）"""
        ciphertext_bin = ""
        for char in text:
            bin_char = format(ord(char), '08b')  # 字符转8位二进制
            cipher_bin = self.encrypt(bin_char)
            ciphertext_bin += cipher_bin
        return ciphertext_bin

    def decrypt_ascii(self, ciphertext_bin):
        """二进制密文 → ASCII字符串（每8位密文解密后转字符）"""
        plaintext = ""
        for i in range(0, len(ciphertext_bin), 8):
            bin_chunk = ciphertext_bin[i:i + 8]
            plain_bin = self.decrypt(bin_chunk)
            plaintext += chr(int(plain_bin, 2))  # 二进制转字符
        return plaintext


def brute_force(known_plain, known_cipher, progress_callback=None):
    """暴力破解：遍历所有10位密钥，找匹配的密钥"""
    matched_keys = []
    total = 2 ** 10  # 10位密钥共1024种可能
    for i in range(total):
        key = format(i, '010b')  # 转10位二进制字符串
        s_des = S_DES(key)
        encrypted = s_des.encrypt(known_plain)
        if encrypted == known_cipher:
            matched_keys.append(key)
        # 进度回调（更新GUI进度条）
        if progress_callback:
            progress = (i + 1) / total * 100
            progress_callback(progress)
    return matched_keys


class S_DES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES加密解密工具（作业1）")
        self.root.geometry("800x650")

        # 多标签页（对应5个关卡）
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 1. 基础测试标签页
        self.tab_basic = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_basic, text="第1关：基础测试")
        self._create_basic_tab()

        # 2. 交叉测试标签页
        self.tab_cross = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_cross, text="第2关：交叉测试")
        self._create_cross_tab()

        # 3. 扩展功能（ASCII）标签页
        self.tab_extend = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_extend, text="第3关：ASCII扩展")
        self._create_extend_tab()

        # 4. 暴力破解标签页
        self.tab_brute = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_brute, text="第4关：暴力破解")
        self._create_brute_tab()

        # 5. 封闭测试标签页
        self.tab_closure = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_closure, text="第5关：封闭测试")
        self._create_closure_tab()

    def _create_basic_tab(self):
        """基础测试：8位二进制明文/密文 + 10位密钥的加解密"""
        # 密钥输入
        ttk.Label(self.tab_basic, text="10位二进制密钥:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry_basic = ttk.Entry(self.tab_basic, width=30)
        self.key_entry_basic.grid(row=0, column=1, padx=5, pady=5)
        self.key_entry_basic.insert(0, "1010000010")  # 示例密钥

        # 明文/密文输入
        ttk.Label(self.tab_basic, text="8位二进制明文/密文:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.text_entry_basic = ttk.Entry(self.tab_basic, width=30)
        self.text_entry_basic.grid(row=1, column=1, padx=5, pady=5)
        self.text_entry_basic.insert(0, "00000000")  # 示例明文

        # 加密按钮
        self.encrypt_btn_basic = ttk.Button(self.tab_basic, text="加密", command=self._basic_encrypt)
        self.encrypt_btn_basic.grid(row=2, column=0, padx=5, pady=10)

        # 解密按钮
        self.decrypt_btn_basic = ttk.Button(self.tab_basic, text="解密", command=self._basic_decrypt)
        self.decrypt_btn_basic.grid(row=2, column=1, padx=5, pady=10)

        # 结果显示
        ttk.Label(self.tab_basic, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.NW)
        self.result_text_basic = tk.Text(self.tab_basic, height=5, width=40)
        self.result_text_basic.grid(row=3, column=1, padx=5, pady=5)

    def _basic_encrypt(self):
        """基础加密逻辑"""
        key = self.key_entry_basic.get()
        text = self.text_entry_basic.get()
        try:
            s_des = S_DES(key)
            cipher = s_des.encrypt(text)
            self.result_text_basic.delete(1.0, tk.END)
            self.result_text_basic.insert(tk.END, f"密文: {cipher}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _basic_decrypt(self):
        """基础解密逻辑"""
        key = self.key_entry_basic.get()
        text = self.text_entry_basic.get()
        try:
            s_des = S_DES(key)
            plain = s_des.decrypt(text)
            self.result_text_basic.delete(1.0, tk.END)
            self.result_text_basic.insert(tk.END, f"明文: {plain}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _create_cross_tab(self):
        """交叉测试：模拟A组加密、B组解密，验证算法一致性"""
        # 密钥输入（A、B组共用）
        ttk.Label(self.tab_cross, text="10位二进制密钥:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry_cross = ttk.Entry(self.tab_cross, width=30)
        self.key_entry_cross.grid(row=0, column=1, padx=5, pady=5)
        self.key_entry_cross.insert(0, "1110001110")  # 示例密钥

        # 明文输入
        ttk.Label(self.tab_cross, text="8位二进制明文:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.plain_entry_cross = ttk.Entry(self.tab_cross, width=30)
        self.plain_entry_cross.grid(row=1, column=1, padx=5, pady=5)
        self.plain_entry_cross.insert(0, "10101010")  # 示例明文

        # 加密按钮（A组加密）
        self.encrypt_btn_cross = ttk.Button(self.tab_cross, text="A组加密", command=self._cross_encrypt)
        self.encrypt_btn_cross.grid(row=2, column=0, padx=5, pady=10)

        # 解密按钮（B组解密）
        self.decrypt_btn_cross = ttk.Button(self.tab_cross, text="B组解密", command=self._cross_decrypt)
        self.decrypt_btn_cross.grid(row=2, column=1, padx=5, pady=10)

        # 结果显示
        ttk.Label(self.tab_cross, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.NW)
        self.result_text_cross = tk.Text(self.tab_cross, height=5, width=40)
        self.result_text_cross.grid(row=3, column=1, padx=5, pady=5)

    def _cross_encrypt(self):
        """A组加密逻辑"""
        key = self.key_entry_cross.get()
        plain = self.plain_entry_cross.get()
        try:
            s_des = S_DES(key)
            cipher = s_des.encrypt(plain)
            self.result_text_cross.delete(1.0, tk.END)
            self.result_text_cross.insert(tk.END, f"A组加密结果: {cipher}")
            self.cross_cipher = cipher  # 保存密文，供B组解密用
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _cross_decrypt(self):
        """B组解密逻辑"""
        if not hasattr(self, 'cross_cipher'):
            messagebox.showinfo("提示", "请先执行“A组加密”")
            return
        key = self.key_entry_cross.get()
        try:
            s_des = S_DES(key)
            plain = s_des.decrypt(self.cross_cipher)
            self.result_text_cross.delete(1.0, tk.END)
            self.result_text_cross.insert(tk.END,
                                          f"A组加密结果: {self.cross_cipher}\nB组解密结果: {plain}\n是否与原明文一致: {plain == self.plain_entry_cross.get()}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _create_extend_tab(self):
        """扩展功能：ASCII字符串的加解密"""
        # ASCII文本输入
        ttk.Label(self.tab_extend, text="ASCII文本:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.NW)
        self.ascii_text = tk.Text(self.tab_extend, height=5, width=40)
        self.ascii_text.grid(row=0, column=1, padx=5, pady=5)
        self.ascii_text.insert(tk.END, "Hello S-DES")  # 示例文本

        # 密钥输入
        ttk.Label(self.tab_extend, text="10位二进制密钥:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry_ascii = ttk.Entry(self.tab_extend, width=30)
        self.key_entry_ascii.grid(row=1, column=1, padx=5, pady=5)
        self.key_entry_ascii.insert(0, "1010101010")  # 示例密钥

        # 加密按钮
        self.encrypt_btn_ascii = ttk.Button(self.tab_extend, text="加密", command=self._ascii_encrypt)
        self.encrypt_btn_ascii.grid(row=2, column=0, padx=5, pady=10)

        # 解密按钮
        self.decrypt_btn_ascii = ttk.Button(self.tab_extend, text="解密", command=self._ascii_decrypt)
        self.decrypt_btn_ascii.grid(row=2, column=1, padx=5, pady=10)

        # 结果显示
        ttk.Label(self.tab_extend, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.NW)
        self.result_text_ascii = tk.Text(self.tab_extend, height=10, width=40)
        self.result_text_ascii.grid(row=3, column=1, padx=5, pady=5)

    def _ascii_encrypt(self):
        """ASCII文本加密逻辑"""
        text = self.ascii_text.get(1.0, tk.END).strip()
        key = self.key_entry_ascii.get()
        try:
            s_des = S_DES(key)
            cipher_bin = s_des.encrypt_ascii(text)
            self.result_text_ascii.delete(1.0, tk.END)
            self.result_text_ascii.insert(tk.END, f"加密后的二进制密文:\n{cipher_bin}")
            self.ascii_cipher = cipher_bin  # 保存密文，供解密用
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _ascii_decrypt(self):
        """ASCII密文解密逻辑"""
        if not hasattr(self, 'ascii_cipher'):
            messagebox.showinfo("提示", "请先执行“加密”")
            return
        key = self.key_entry_ascii.get()
        try:
            s_des = S_DES(key)
            plain_text = s_des.decrypt_ascii(self.ascii_cipher)
            self.result_text_ascii.delete(1.0, tk.END)
            self.result_text_ascii.insert(tk.END,
                                          f"加密后的二进制密文:\n{self.ascii_cipher}\n解密后的ASCII文本:\n{plain_text}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _create_brute_tab(self):
        """暴力破解：多线程遍历密钥，带进度条和破解时间显示"""
        # 已知明文输入
        ttk.Label(self.tab_brute, text="已知8位二进制明文:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.known_plain_entry = ttk.Entry(self.tab_brute, width=30)
        self.known_plain_entry.grid(row=0, column=1, padx=5, pady=5)
        self.known_plain_entry.insert(0, "00000000")  # 示例明文

        # 已知密文输入
        ttk.Label(self.tab_brute, text="已知8位二进制密文:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.known_cipher_entry = ttk.Entry(self.tab_brute, width=30)
        self.known_cipher_entry.grid(row=1, column=1, padx=5, pady=5)
        self.known_cipher_entry.insert(0, "11001011")  # 示例密文

        # 暴力破解按钮
        self.brute_btn = ttk.Button(self.tab_brute, text="开始暴力破解", command=self._start_brute)
        self.brute_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # 进度条
        ttk.Label(self.tab_brute, text="破解进度:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.progress_bar = ttk.Progressbar(self.tab_brute, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.grid(row=3, column=1, padx=5, pady=5)

        # 结果显示
        ttk.Label(self.tab_brute, text="匹配的密钥:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.NW)
        self.result_text_brute = tk.Text(self.tab_brute, height=5, width=40)
        self.result_text_brute.grid(row=4, column=1, padx=5, pady=5)

        # 破解耗时显示
        ttk.Label(self.tab_brute, text="破解耗时:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.time_label_brute = ttk.Label(self.tab_brute, text="")  # 初始为空，后续更新
        self.time_label_brute.grid(row=5, column=1, padx=5, pady=5)

    def _update_progress(self, progress):
        """更新进度条（线程安全）"""
        self.progress_bar["value"] = progress
        self.root.update_idletasks()  # 强制更新UI

    def _start_brute(self):
        """启动暴力破解（多线程，避免UI卡死）"""
        known_plain = self.known_plain_entry.get()
        known_cipher = self.known_cipher_entry.get()
        self.result_text_brute.delete(1.0, tk.END)
        self.time_label_brute.config(text="")  # 清空之前的耗时
        self.progress_bar["value"] = 0

        def brute_task():
            """暴力破解的任务函数（放线程中执行）"""
            try:
                start_time = time.time()  # 记录开始时间
                # 多线程执行暴力破解，带进度回调
                with ThreadPoolExecutor() as executor:
                    future = executor.submit(brute_force, known_plain, known_cipher, self._update_progress)
                    matched_keys = future.result()
                end_time = time.time()  # 记录结束时间
                elapsed_ms = (end_time - start_time) * 1000  # 计算耗时（毫秒）

                # 显示匹配的密钥
                self.result_text_brute.delete(1.0, tk.END)
                if matched_keys:
                    self.result_text_brute.insert(tk.END, "匹配的密钥：\n" + "\n".join(matched_keys))
                else:
                    self.result_text_brute.insert(tk.END, "未找到匹配的密钥")

                # 显示破解耗时
                self.time_label_brute.config(text=f"耗时：{elapsed_ms:.2f} 毫秒")
            except Exception as e:
                messagebox.showerror("错误", str(e))

        # 开启新线程执行，避免阻塞UI
        threading.Thread(target=brute_task, daemon=True).start()

    def _create_closure_tab(self):
        """封闭测试：多次加密同一明文，观察是否回到原明文"""
        # 明文输入
        ttk.Label(self.tab_closure, text="8位二进制明文:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.plain_entry_closure = ttk.Entry(self.tab_closure, width=30)
        self.plain_entry_closure.grid(row=0, column=1, padx=5, pady=5)
        self.plain_entry_closure.insert(0, "10101010")  # 示例明文

        # 密钥输入
        ttk.Label(self.tab_closure, text="10位二进制密钥:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry_closure = ttk.Entry(self.tab_closure, width=30)
        self.key_entry_closure.grid(row=1, column=1, padx=5, pady=5)
        self.key_entry_closure.insert(0, "1100110011")  # 示例密钥

        # 测试轮次数
        ttk.Label(self.tab_closure, text="测试轮次数:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.rounds_entry = ttk.Entry(self.tab_closure, width=10)
        self.rounds_entry.grid(row=2, column=1, padx=5, pady=5)
        self.rounds_entry.insert(0, "5")  # 示例轮次

        # 开始测试按钮
        self.closure_btn = ttk.Button(self.tab_closure, text="开始封闭测试", command=self._run_closure_test)
        self.closure_btn.grid(row=3, column=0, columnspan=2, pady=10)

        # 结果显示
        ttk.Label(self.tab_closure, text="测试结果:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.NW)
        self.result_text_closure = tk.Text(self.tab_closure, height=10, width=40)
        self.result_text_closure.grid(row=4, column=1, padx=5, pady=5)

    def _run_closure_test(self):
        """封闭测试逻辑：多次加密同一明文"""
        plain = self.plain_entry_closure.get()
        key = self.key_entry_closure.get()
        try:
            rounds = int(self.rounds_entry.get())
            s_des = S_DES(key)
            current = plain
            results = []
            for i in range(rounds):
                current = s_des.encrypt(current)
                results.append(f"第{i + 1}轮加密结果: {current}")
                if current == plain:
                    results.append("→ 回到初始明文！（封闭性验证成功）")
                    break  # 提前结束，因为已回到明文
            # 显示结果
            self.result_text_closure.delete(1.0, tk.END)
            self.result_text_closure.insert(tk.END, "\n".join(results))
        except ValueError:
            messagebox.showerror("错误", "轮次数必须是整数")
        except Exception as e:
            messagebox.showerror("错误", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = S_DES_GUI(root)
    root.mainloop()
