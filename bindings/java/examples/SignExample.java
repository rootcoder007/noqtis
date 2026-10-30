// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import io.github.rootcoder007.noqtis.Sign;
import java.nio.charset.StandardCharsets;

public class SignExample {
  public static void main(String[] args) {
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    Sign.Opts o = Sign.Opts.none().withCtx("app-v1".getBytes(StandardCharsets.UTF_8));
    byte[] msg = "the results in table 2".getBytes(StandardCharsets.UTF_8);
    byte[] sig = Sign.sign("ML-DSA-65", k.sk(), msg, o);
    System.out.println("signature: " + sig.length + " bytes");
    System.out.println("verify: " + Sign.verify("ML-DSA-65", k.pk(), msg, sig, o));
    byte[] other = "other".getBytes(StandardCharsets.UTF_8);
    System.out.println("other message: " + Sign.verify("ML-DSA-65", k.pk(), other, sig, o));
  }
}
