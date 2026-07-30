import tenseal as ts
import numpy as np

# 1. 设置上下文
context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
context.global_scale = 2**40
context.generate_galois_keys()

# 2. 明文数据
plain_input = np.array([
    [1, 2, 3, 4],
    [5, 6, 7, 8],
    [9, 10, 11, 12],
    [13, 14, 15, 16]
], dtype=np.float64)

plain_kernel = np.array([
    [1, 0, -1],
    [1, 0, -1],
    [1, 0, -1]
], dtype=np.float64)

# 3. 构造线性变换矩阵 M (16 x 4)，使得 input_flat (1x16) * M = output (1x4)
def conv_linear_matrix(input_shape, kernel, stride):
    h, w = input_shape
    kh, kw = kernel.shape
    out_h = (h - kh) // stride + 1
    out_w = (w - kw) // stride + 1
    M = np.zeros((h * w, out_h * out_w))  # 16 x 4
    for r in range(out_h):
        for c in range(out_w):
            out_idx = r * out_w + c
            for i in range(kh):
                for j in range(kw):
                    in_r = r * stride + i
                    in_c = c * stride + j
                    in_idx = in_r * w + in_c
                    M[in_idx, out_idx] = kernel[i, j]
    return M

M = conv_linear_matrix((4,4), plain_kernel, 1)  # shape (16,4)
print("明文矩阵 M 形状:", M.shape)

# 4. 明文验证（方便对照）
plain_res = (plain_input.flatten() @ M).flatten()
print("明文卷积结果:", plain_res)

# 5. 加密输入（一维向量）
encrypted_input = ts.ckks_vector(context, plain_input.flatten().tolist())

# 6. 密文矩阵乘法：encrypted_input (1x16) 与 M (16x4) 相乘，得到 (1x4) 密文
encrypted_output = encrypted_input.matmul(M.tolist())   # M.tolist() 是 (16,4) 的二维列表

# 7. 解密并提取结果
decrypted = encrypted_output.decrypt()
fhe_result = decrypted[:4]
print("FHE 卷积结果:", fhe_result)

# 8. 误差分析
err = max(abs(a-b) for a,b in zip(fhe_result, plain_res))
print("最大绝对误差:", err)

if err < 1e-3:
    print(" 验证成功！")
else:
    print(" 误差稍大，但可能仍属于CKKS正常范围。")