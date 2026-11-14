using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ESCloud.Contracts;

namespace ESCloud.Collector;

public static class GraphJson
{
    public static CbaPolicy ReadCba(JsonElement root)
    {
        var policy = new CbaPolicy
        {
            State = StringOf(root, "state")
        };

        if (root.TryGetProperty("certificateUserBindings", out var bindings) && bindings.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in bindings.EnumerateArray())
            {
                policy.CertificateUserBindings.Add(new CertificateUserBinding
                {
                    X509CertificateField = CanonicalField(StringOf(item, "x509CertificateField")),
                    UserProperty = CanonicalUserProperty(StringOf(item, "userProperty")),
                    Priority = item.TryGetProperty("priority", out var priority) && priority.TryGetInt32(out var number) ? number : 0
                });
            }
        }

        if (root.TryGetProperty("authenticationModeConfiguration", out var mode))
        {
            policy.AuthenticationModeConfiguration.X509CertificateAuthenticationDefaultMode =
                CanonicalMode(StringOf(mode, "x509CertificateAuthenticationDefaultMode"));
            if (mode.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Array)
            {
                foreach (var rule in rules.EnumerateArray())
                {
                    policy.AuthenticationModeConfiguration.Rules.Add(new AuthenticationModeRule
                    {
                        X509CertificateRuleType = StringOf(rule, "x509CertificateRuleType"),
                        Identifier = StringOf(rule, "identifier"),
                        X509CertificateAuthenticationMode = CanonicalMode(StringOf(rule, "x509CertificateAuthenticationMode"))
                    });
                }
            }
        }

        if (root.TryGetProperty("crlValidationConfiguration", out var crl))
        {
            policy.CrlValidationConfiguration.State = StringOf(crl, "state");
            if (crl.TryGetProperty("exemptedCertificateAuthoritiesSubjectKeyIdentifiers", out var exempted)
                && exempted.ValueKind == JsonValueKind.Array)
            {
                policy.CrlValidationConfiguration.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers =
                    exempted.EnumerateArray().Select(item => item.GetString() ?? "").Where(s => s.Length > 0).ToList();
            }
        }

        policy.CertificateAuthorityScopes = ReadScopes(root, "certificateAuthorityScopes");
        policy.IncludeTargets = ReadTargets(root, "includeTargets");
        policy.ExcludeTargets = ReadTargets(root, "excludeTargets");
        return policy;
    }

    public static List<TrustedCertificateAuthority> ReadClassicTrust(JsonElement root)
    {
        var array = root.TryGetProperty("certificateAuthorities", out var authorities)
            ? authorities
            : root.TryGetProperty("value", out var value) ? value : default;
        if (array.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var list = new List<TrustedCertificateAuthority>();
        foreach (var item in array.EnumerateArray())
        {
            list.Add(ReadAuthority(item, "classic"));
        }

        return list;
    }

    public static List<TrustedCertificateAuthority> ReadPkiTrust(JsonElement root)
    {
        if (!root.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var list = new List<TrustedCertificateAuthority>();
        foreach (var config in value.EnumerateArray())
        {
            var pkiId = FirstString(config, "id", "publicKeyInfrastructureIdentifier");
            JsonElement authorities = default;
            foreach (var name in new[] { "trustedCertificateAuthorities", "certificateAuthorities" })
            {
                if (config.TryGetProperty(name, out var found) && found.ValueKind == JsonValueKind.Array)
                {
                    authorities = found;
                    break;
                }
            }

            if (authorities.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var item in authorities.EnumerateArray())
            {
                var ca = ReadAuthority(item, "pki-based");
                ca.PublicKeyInfrastructureIdentifier = pkiId;
                list.Add(ca);
            }
        }

        return list;
    }

    public static IntuneCertProfile? ReadIntuneProfile(JsonElement item)
    {
        var odata = StringOf(item, "@odata.type");
        var blob = item.GetRawText();
        var looksLikeCert = odata.Contains("scep", StringComparison.OrdinalIgnoreCase)
            || odata.Contains("pkcs", StringComparison.OrdinalIgnoreCase)
            || blob.Contains("subjectNameFormat", StringComparison.OrdinalIgnoreCase)
            || blob.Contains("ScepCertificate", StringComparison.OrdinalIgnoreCase)
            || blob.Contains("PkcsCertificate", StringComparison.OrdinalIgnoreCase);
        if (!looksLikeCert)
        {
            return null;
        }

        var subject = FirstString(item,
            "subjectNameFormat",
            "subjectNameFormatString",
            "subjectNameFormatStringForNdes");
        var sans = ReadStringList(item, "sanFormat");
        if (sans.Count == 0)
        {
            var single = FirstString(item, "subjectAlternativeNameFormatString", "customSubjectAlternativeName");
            if (!string.IsNullOrWhiteSpace(single))
            {
                sans.Add(single);
            }
        }

        sans.AddRange(ExtractTemplates(blob).Where(template => !sans.Contains(template, StringComparer.OrdinalIgnoreCase)));

        var keyUsage = ReadStringList(item, "keyUsage");
        if (keyUsage.Count == 1 && keyUsage[0].Contains(','))
        {
            keyUsage = keyUsage[0].Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        }

        var ekus = ReadEkus(item);
        var store = FirstString(item, "certificateStore", "certStore");
        var type = odata.Contains("pkcs", StringComparison.OrdinalIgnoreCase) ? "PKCS"
            : odata.Contains("scep", StringComparison.OrdinalIgnoreCase) ? "SCEP"
            : blob.Contains("PKCS", StringComparison.OrdinalIgnoreCase) ? "PKCS" : "SCEP";

        var joined = subject + "\n" + string.Join("\n", sans);
        var sid = joined.Contains("OnPremisesSecurityIdentifier", StringComparison.OrdinalIgnoreCase)
            || joined.Contains("1.3.6.1.4.1.311.25.2", StringComparison.Ordinal);

        return new IntuneCertProfile
        {
            Id = FirstString(item, "id") ?? "",
            DisplayName = FirstString(item, "displayName"),
            Type = type,
            ODataType = string.IsNullOrWhiteSpace(odata) ? null : odata,
            SubjectNameFormat = subject,
            SanFormat = sans,
            KeyUsage = keyUsage,
            Ekus = ekus,
            HasSidStrongMapping = sid,
            CertStore = store
        };
    }

    public static TrustedCertificateAuthority ReadAuthority(JsonElement item, string source)
    {
        var certificate = FirstString(item, "certificate");
        var issuer = FirstString(item, "issuer", "issuerName", "subject");
        var ski = FirstString(item, "issuerSki", "subjectKeyIdentifier", "issuerSubjectKeyIdentifier");
        var parsed = TryReadCertificate(certificate);
        if (parsed is not null)
        {
            issuer = string.IsNullOrWhiteSpace(issuer) ? parsed.Value.Subject : issuer;
            ski = string.IsNullOrWhiteSpace(ski) ? parsed.Value.Ski : ski;
        }

        return new TrustedCertificateAuthority
        {
            IsRootAuthority = item.TryGetProperty("isRootAuthority", out var root) && root.ValueKind == JsonValueKind.True,
            Issuer = issuer ?? "",
            SubjectKeyIdentifier = ski,
            CertificateRevocationListUrl = FirstString(item, "certificateRevocationListUrl", "crlDistributionPoint"),
            DeltaCertificateRevocationListUrl = FirstString(item, "deltaCertificateRevocationListUrl"),
            Certificate = certificate,
            Source = source,
            IsPublic = PublicCaNames.IsPublic(issuer) || PublicCaNames.IsPublic(parsed?.Subject),
            PublicKeyInfrastructureIdentifier = FirstString(item, "publicKeyInfrastructureIdentifier")
        };
    }

    private static List<CertificateAuthorityScope> ReadScopes(JsonElement root, string name)
    {
        var list = new List<CertificateAuthorityScope>();
        if (!root.TryGetProperty(name, out var scopes) || scopes.ValueKind != JsonValueKind.Array)
        {
            return list;
        }

        foreach (var scope in scopes.EnumerateArray())
        {
            list.Add(new CertificateAuthorityScope
            {
                SubjectKeyIdentifier = FirstString(scope, "subjectKeyIdentifier"),
                PublicKeyInfrastructureIdentifier = FirstString(scope, "publicKeyInfrastructureIdentifier"),
                IncludeTargets = ReadTargets(scope, "includeTargets")
            });
        }

        return list;
    }

    private static List<AuthenticationMethodTarget> ReadTargets(JsonElement root, string name)
    {
        var list = new List<AuthenticationMethodTarget>();
        if (!root.TryGetProperty(name, out var targets) || targets.ValueKind != JsonValueKind.Array)
        {
            return list;
        }

        foreach (var target in targets.EnumerateArray())
        {
            bool? registration = null;
            if (target.TryGetProperty("isRegistrationRequired", out var flag) && flag.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                registration = flag.GetBoolean();
            }

            list.Add(new AuthenticationMethodTarget
            {
                TargetType = StringOf(target, "targetType"),
                Id = StringOf(target, "id"),
                IsRegistrationRequired = registration
            });
        }

        return list;
    }

    private static List<string> ReadEkus(JsonElement item)
    {
        var ekus = new List<string>();
        foreach (var name in new[] { "ekus", "extendedKeyUsages", "customKeyUsages" })
        {
            if (!item.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var entry in array.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String)
                {
                    var text = entry.GetString();
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        ekus.Add(text);
                    }
                }
                else if (entry.ValueKind == JsonValueKind.Object)
                {
                    var oid = FirstString(entry, "objectIdentifier", "oid", "value");
                    if (!string.IsNullOrWhiteSpace(oid))
                    {
                        ekus.Add(oid);
                    }
                }
            }
        }

        return ekus;
    }

    private static List<string> ReadStringList(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return array.EnumerateArray()
            .Where(entry => entry.ValueKind == JsonValueKind.String)
            .Select(entry => entry.GetString() ?? "")
            .Where(text => text.Length > 0)
            .ToList();
    }

    private static List<string> ExtractTemplates(string blob)
    {
        var found = new List<string>();
        var index = 0;
        while (index < blob.Length)
        {
            var start = blob.IndexOf("{{", index, StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            var end = blob.IndexOf("}}", start, StringComparison.Ordinal);
            if (end < 0)
            {
                break;
            }

            found.Add(blob[start..(end + 2)]);
            index = end + 2;
        }

        return found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static (string Subject, string? Ski)? TryReadCertificate(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
        {
            return null;
        }

        try
        {
            var bytes = Convert.FromBase64String(encoded);
            using var cert = new X509Certificate2(bytes);
            var ski = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier;
            return (cert.Subject, ski);
        }
        catch (FormatException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    public static string CanonicalField(string value) => value.ToLowerInvariant() switch
    {
        "principalname" => "PrincipalName",
        "rfc822name" => "RFC822Name",
        "subjectkeyidentifier" => "SubjectKeyIdentifier",
        "sha1publickey" => "SHA1PublicKey",
        _ => value
    };

    public static string CanonicalUserProperty(string value) => value.ToLowerInvariant() switch
    {
        "userprincipalname" => "userPrincipalName",
        "onpremisesuserprincipalname" => "onPremisesUserPrincipalName",
        "certificateuserids" => "certificateUserIds",
        _ => value
    };

    public static string CanonicalMode(string value) => value.ToLowerInvariant() switch
    {
        "x509certificatesinglefactor" => "x509CertificateSingleFactor",
        "x509certificatemultifactor" => "x509CertificateMultiFactor",
        _ => value
    };

    private static string StringOf(JsonElement element, string name)
    {
        return FirstString(element, name) ?? "";
    }

    private static string? FirstString(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    return text;
                }
            }
        }

        return null;
    }
}
