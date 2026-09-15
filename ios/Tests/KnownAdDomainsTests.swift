#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class KnownAdDomainsTests: XCTestCase {
    func testCatalogCountAndUniqueness() {
        XCTAssertEqual(KnownAdDomains.suffixes.count, 40)
        let normalized = KnownAdDomains.suffixes.map(KnownAdDomains.normalize)
        XCTAssertEqual(Set(normalized).count, normalized.count)
        XCTAssertFalse(normalized.contains { $0.isEmpty })
    }

    func testCatalogKeepsMolocoWithoutLeadingDot() {
        XCTAssertTrue(KnownAdDomains.suffixes.contains("adsmoloco.com"))
        XCTAssertEqual(KnownAdDomains.normalize("adsmoloco.com"), "adsmoloco.com")
        XCTAssertEqual(KnownAdDomains.normalize(".adsmoloco.com"), "adsmoloco.com")
    }

    func testDomainsToInsertSkipsExistingHostSuffix() {
        let existing = [
            TestSupport.rule(selectorType: .hostSuffix, selectorValue: ".applovin.com"),
            TestSupport.rule(selectorType: .host, selectorValue: ".vungle.com"),
        ]
        let selected = [".applovin.com", ".vungle.com", "applovin.com"]
        XCTAssertEqual(
            KnownAdDomains.domainsToInsert(from: selected, existingRules: existing),
            [".vungle.com"]
        )
    }

    func testDomainsToInsertEmptyWhenAllPresent() {
        let existing = KnownAdDomains.suffixes.enumerated().map { index, domain in
            TestSupport.rule(id: Int64(index + 1), selectorType: .hostSuffix, selectorValue: domain)
        }
        XCTAssertTrue(KnownAdDomains.domainsToInsert(from: KnownAdDomains.suffixes, existingRules: existing).isEmpty)
    }

    func testCatalogSuffixBlocksSubdomain() {
        let engine = RuleEngineImpl()
        engine.updateRules([
            TestSupport.rule(selectorType: .hostSuffix, selectorValue: KnownAdDomains.suffixes[12]),
        ])
        XCTAssertEqual(KnownAdDomains.suffixes[12], ".applovin.com")
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "prod.applovin.com")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "applovin.com")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "notapplovin.com")), .defaultAllow)
    }
}
