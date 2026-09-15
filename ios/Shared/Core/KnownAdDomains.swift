import Foundation

/// Built-in HOST_SUFFIX catalog of known ad / tracker domains.
public enum KnownAdDomains {
    public static let suffixes: [String] = [
        ".wunityads.unity3d.com",
        ".adsafeprotected.com",
        ".googleads.g.doubleclick.net",
        ".pubads.g.doubleclick.net",
        ".vungle.com",
        ".googleadservices.com",
        ".adjust.net.in",
        ".kwcdn.com",
        "adsmoloco.com",
        ".bidmachine.io",
        ".moloco.com",
        ".axon.ai",
        ".applovin.com",
        ".3lift.com",
        ".nefta.app",
        ".mtgglobals.com",
        ".saygames.io",
        ".safedk.com",
        ".tiktokcdn.com",
        ".ibyteimg.com",
        ".sng.link",
        ".pangle.io",
        ".byteoversea.com",
        ".adnxs.com",
        ".doubleverify.com",
        ".tagsrvcs.com",
        ".adskprod.azureedge.net",
        ".lazybumblebee.com",
        ".smartbid.ai",
        ".liftoff.io",
        ".inmobi.com",
        ".everstop.io",
        ".blueduckredapple.com",
        ".cloud.unity3d.com",
        ".applvn.com",
        ".amazon-adsystem.com",
        ".appsflyersdk.com",
        ".inmobicdn.net",
        ".kayzen.io",
        ".tenjin.io",
    ]

    public static func normalize(_ value: String) -> String {
        var s = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while s.hasPrefix(".") {
            s.removeFirst()
        }
        return s
    }

    /// Catalog strings still missing as HOST_SUFFIX rules, preserving selection order.
    public static func domainsToInsert(from selected: [String], existingRules: [Rule]) -> [String] {
        var seen = Set(
            existingRules
                .filter { $0.selectorType == .hostSuffix }
                .map { normalize($0.selectorValue) }
                .filter { !$0.isEmpty }
        )
        var result: [String] = []
        for domain in selected {
            let key = normalize(domain)
            guard !key.isEmpty, !seen.contains(key) else { continue }
            seen.insert(key)
            result.append(domain)
        }
        return result
    }
}
