namespace ESCloud.Contracts;

/// <summary>
/// Name fragments for well-known public roots. Used only to set <c>isPublic</c>.
/// A bare "Microsoft" match is intentionally absent so a lab CA named after Microsoft
/// is not treated as a public root.
/// </summary>
public static class PublicCaNames
{
    private static readonly string[] Fragments =
    [
        "DigiCert",
        "GlobalSign",
        "ISRG Root",
        "Let's Encrypt",
        "Lets Encrypt",
        "Sectigo",
        "Comodo",
        "Amazon Root",
        "Google Trust Services",
        "Baltimore CyberTrust",
        "Entrust",
        "VeriSign",
        "USERTrust",
        "Starfield",
        "Go Daddy",
        "GoDaddy",
        "IdenTrust",
        "QuoVadis",
        "SwissSign",
        "Buypass",
        "SSL.com",
        "Actalis",
        "Certum",
        "HARICA",
        "Microsoft Azure TLS",
        "Microsoft RSA TLS",
        "Microsoft ECC TLS",
        "DigiCert Global Root"
    ];

    public static bool IsPublic(string? issuerOrSubject)
    {
        if (string.IsNullOrWhiteSpace(issuerOrSubject))
        {
            return false;
        }

        foreach (var fragment in Fragments)
        {
            if (issuerOrSubject.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
