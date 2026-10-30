// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import io.github.rootcoder007.noqtis.IdCard;
import io.github.rootcoder007.noqtis.NoqtisException;
import io.github.rootcoder007.noqtis.Sign;
import java.nio.charset.StandardCharsets;

public class CardExample {
  public static void main(String[] args) {
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    IdCard.Fields f =
        IdCard.Fields.of("Ada Lovelace")
            .withOrcid("https://orcid.org/0000-0002-1825-0097")
            .withUrl("https://example.org/ada");
    byte[] card = IdCard.make("ML-DSA-65", k.sk(), k.pk(), f, null);

    IdCard.Card c = IdCard.verify(card, k.pk()); // null unless it verifies and is k's
    System.out.println("name: " + c.name());
    System.out.println("orcid: " + c.orcid());

    // a changed card does not verify; a wrong check digit is refused
    String t = new String(card, StandardCharsets.UTF_8).replace("Ada", "Eve");
    System.out.println("changed: " + IdCard.verify(t.getBytes(StandardCharsets.UTF_8), null));
    try {
      IdCard.make("ML-DSA-65", k.sk(), k.pk(), f.withOrcid("0000-0002-1825-0098"), null);
    } catch (NoqtisException e) {
      System.out.println("refused: " + e.kind());
    }
  }
}
