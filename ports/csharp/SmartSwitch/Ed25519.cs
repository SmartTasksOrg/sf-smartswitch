using System.Numerics;
using System.Security.Cryptography;

namespace SmartSwitch;

/// <summary>
/// Ed25519 signature verification (RFC 8032), verify only, written for this port after the reference code
/// in RFC 8032 section 6, with System.Numerics.BigInteger. It has not been independently audited. It
/// passes the RFC 8032 test vectors and the shared vectors in spec/conformance/ed25519.json. It verifies
/// public data and makes no attempt at constant time.
/// <para>
/// <see cref="Verify"/> applies the engine's pre-checks first (spec/SEMANTICS.md, "Signatures"):
/// lower-case hex of the right length and S &lt; L. Then it decodes A and R, rejecting y &gt;= p and points
/// that are not on the curve (no square root, or x = 0 with the sign bit set), and checks the
/// cofactorless equation [S]B == R + [k]A with k = SHA-512(R || A || M) mod L.
/// </para>
/// </summary>
public static class Ed25519
{
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    public static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    static readonly BigInteger D = Mod(-121665 * Inv(121666));
    static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
    static readonly Point B = BasePoint();

    readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    static BigInteger Mod(BigInteger a)
    {
        var r = a % P;
        return r.Sign < 0 ? r + P : r;
    }

    static BigInteger Inv(BigInteger x) => BigInteger.ModPow(Mod(x), P - 2, P);

    static Point BasePoint()
    {
        var y = Mod(4 * Inv(5));
        var x = RecoverX(y, 0) ?? throw new InvalidOperationException("base point");
        return new Point(x, y, 1, Mod(x * y));
    }

    static Point Add(Point p, Point q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X));
        var b = Mod((p.Y + p.X) * (q.Y + q.X));
        var c = Mod(2 * p.T * q.T * D);
        var d = Mod(2 * p.Z * q.Z);
        var e = b - a;
        var f = d - c;
        var g = d + c;
        var h = b + a;
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    static Point Mul(BigInteger s, Point p)
    {
        var q = new Point(0, 1, 1, 0);
        while (s.Sign > 0)
        {
            if (!s.IsEven) q = Add(q, p);
            p = Add(p, p);
            s >>= 1;
        }
        return q;
    }

    static bool Equal(Point p, Point q) =>
        Mod(p.X * q.Z - q.X * p.Z).IsZero && Mod(p.Y * q.Z - q.Y * p.Z).IsZero;

    static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y >= P) return null;
        var x2 = Mod((y * y - 1) * Inv(D * y * y + 1));
        if (x2.IsZero) return sign == 1 ? null : BigInteger.Zero;
        var x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (!Mod(x * x - x2).IsZero) x = Mod(x * SqrtM1);
        if (!Mod(x * x - x2).IsZero) return null;
        if ((int)(x & 1) != sign) x = P - x;
        return x;
    }

    static Point? Decompress(ReadOnlySpan<byte> s)
    {
        var bytes = s.ToArray();
        var sign = bytes[31] >> 7;
        bytes[31] &= 0x7f;
        var y = new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
        var x = RecoverX(y, sign);
        if (x == null) return null;
        return new Point(x.Value, y, 1, Mod(x.Value * y));
    }

    /// <summary><paramref name="s"/> is exactly <paramref name="n"/> lower-case hex characters.</summary>
    public static bool IsLowerHex(string? s, int n) => s != null && s.Length == n && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>A public key: 64 lower-case hex characters.</summary>
    public static bool IsKeyHex(object? s) => s is string t && IsLowerHex(t, 64);

    /// <summary>True only for a valid signature <paramref name="sigHex"/> (128 lower-case hex) by
    /// <paramref name="publicHex"/> (64 lower-case hex) over <paramref name="message"/>. Never throws.</summary>
    public static bool Verify(string? publicHex, byte[] message, string? sigHex)
    {
        try
        {
            if (!IsLowerHex(publicHex, 64) || !IsLowerHex(sigHex, 128)) return false;
            var pk = Convert.FromHexString(publicHex!);
            var sig = Convert.FromHexString(sigHex!);
            var s = new BigInteger(sig.AsSpan(32, 32), isUnsigned: true, isBigEndian: false);
            if (s >= L) return false;
            var a = Decompress(pk);
            var r = Decompress(sig.AsSpan(0, 32));
            if (a == null || r == null) return false;
            var h = new byte[64 + message.Length];
            sig.AsSpan(0, 32).CopyTo(h);
            pk.CopyTo(h, 32);
            message.CopyTo(h, 64);
            var k = new BigInteger(SHA512.HashData(h), isUnsigned: true, isBigEndian: false) % L;
            return Equal(Mul(s, B), Add(r.Value, Mul(k, a.Value)));
        }
        catch (Exception e) when (e is ArgumentException or FormatException or OverflowException)
        {
            return false;
        }
    }
}
