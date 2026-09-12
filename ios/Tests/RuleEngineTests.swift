#if canImport(EklabAdBlocker)
@testable import EklabAdBlocker
#else
@testable import TrafficInspectorCore
#endif
import XCTest

final class RuleEngineTests: XCTestCase {
    private var engine: RuleEngineImpl!

    override func setUp() {
        engine = RuleEngineImpl()
    }

    func testAppExactMatchBlocks() {
        engine.updateRules([TestSupport.rule(selectorType: .app, selectorValue: "com.example.app")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(appPackage: "com.example.app")), .block(ruleId: 1))
    }

    func testAppDifferentPackageDoesNotMatch() {
        engine.updateRules([TestSupport.rule(selectorType: .app, selectorValue: "com.other.app")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(appPackage: "com.example.app")), .defaultAllow)
    }

    func testHostExactMatchBlocks() {
        engine.updateRules([TestSupport.rule(selectorValue: "ads.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .block(ruleId: 1))
    }

    func testHostMatchIsCaseInsensitive() {
        engine.updateRules([TestSupport.rule(selectorValue: "ADS.Example.COM")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .block(ruleId: 1))
    }

    func testHostTrailingDotToleratedOnBothSides() {
        engine.updateRules([TestSupport.rule(selectorValue: "ads.example.com.")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .block(ruleId: 1))

        engine.updateRules([TestSupport.rule(selectorValue: "ads.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(dnsHostname: "ads.example.com.")), .block(ruleId: 1))
    }

    func testHostMatchesAnyCandidate() {
        engine.updateRules([TestSupport.rule(selectorValue: "ads.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(dnsHostname: "ads.example.com")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(resolvedHostname: "ads.example.com")), .block(ruleId: 1))
        XCTAssertEqual(
            engine.evaluate(TestSupport.flow(sni: "other.com", dnsHostname: "ads.example.com")),
            .block(ruleId: 1)
        )
    }

    func testHostNoCandidateDoesNotThrow() {
        engine.updateRules([TestSupport.rule(selectorValue: "ads.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow()), .defaultAllow)
    }

    func testHostSuffixMatchesBaseDomain() {
        engine.updateRules([TestSupport.rule(selectorType: .hostSuffix, selectorValue: "x.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "x.com")), .block(ruleId: 1))
    }

    func testHostSuffixMatchesSubdomainAndDeepSubdomain() {
        engine.updateRules([TestSupport.rule(selectorType: .hostSuffix, selectorValue: "x.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.x.com")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "deep.ads.x.com")), .block(ruleId: 1))
    }

    func testHostSuffixSelectorWithLeadingDot() {
        engine.updateRules([TestSupport.rule(selectorType: .hostSuffix, selectorValue: ".x.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.x.com")), .block(ruleId: 1))
    }

    func testHostSuffixNegativeCases() {
        engine.updateRules([TestSupport.rule(selectorType: .hostSuffix, selectorValue: "x.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "notx.com")), .defaultAllow)
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "x.com.evil.com")), .defaultAllow)
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "example.com")), .defaultAllow)
    }

    func testIpExactMatch() {
        engine.updateRules([TestSupport.rule(selectorType: .ip, selectorValue: "1.2.3.4")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "1.2.3.4")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "1.2.3.5")), .defaultAllow)
    }

    func testIpLeadingZerosMatchNumerically() {
        engine.updateRules([TestSupport.rule(selectorType: .ip, selectorValue: "1.2.3.4")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "01.2.3.4")), .block(ruleId: 1))
    }

    func testIpCidrMatchAndNonMatch() {
        engine.updateRules([TestSupport.rule(selectorType: .ip, selectorValue: "1.2.3.0/24")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "1.2.3.77")), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "1.2.4.1")), .defaultAllow)
    }

    func testIpMalformedValuesNeverMatchNeverThrow() {
        engine.updateRules([
            TestSupport.rule(id: 1, selectorType: .ip, selectorValue: "1.2.3.0/33"),
            TestSupport.rule(id: 2, selectorType: .ip, selectorValue: "1.2.3/24"),
            TestSupport.rule(id: 3, selectorType: .ip, selectorValue: "not-an-ip"),
            TestSupport.rule(id: 4, selectorType: .ip, selectorValue: "1.2.3.4/24/8"),
            TestSupport.rule(id: 5, selectorType: .ip, selectorValue: "1.2.3.0/abc"),
        ])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "1.2.3.4")), .defaultAllow)
    }

    func testIpIpv6ExactMatchCaseInsensitive() {
        engine.updateRules([TestSupport.rule(selectorType: .ip, selectorValue: "2001:DB8::1")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(destIp: "2001:db8::1")), .block(ruleId: 1))
    }

    func testTypeMatchIsCaseInsensitive() {
        engine.updateRules([TestSupport.rule(selectorType: .type, selectorValue: "quic")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(protocolType: .quic)), .block(ruleId: 1))
        XCTAssertEqual(engine.evaluate(TestSupport.flow(protocolType: .https)), .defaultAllow)
    }

    func testTypeUnknownNameNeverMatches() {
        engine.updateRules([TestSupport.rule(selectorType: .type, selectorValue: "GOPHER")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(protocolType: .https)), .defaultAllow)
    }

    func testLowerPriorityValueWins() {
        engine.updateRules([
            TestSupport.rule(id: 1, priority: 50, selectorValue: "ads.example.com"),
            TestSupport.rule(id: 2, priority: 10, selectorType: .hostSuffix, selectorValue: "example.com"),
        ])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .block(ruleId: 2))
    }

    func testFirstMatchWinsRegardlessOfAction() {
        engine.updateRules([
            TestSupport.rule(id: 1, priority: 10, selectorValue: "ads.example.com", action: .allow),
            TestSupport.rule(id: 2, priority: 20, selectorType: .hostSuffix, selectorValue: "example.com", action: .block),
        ])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .allow(ruleId: 1))
    }

    func testDisabledRulesIgnored() {
        engine.updateRules([TestSupport.rule(id: 1, enabled: false, selectorValue: "ads.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .defaultAllow)
    }

    func testEmptyRuleSetDefaultAllow() {
        engine.updateRules([])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .defaultAllow)
    }

    func testBeforeAnyUpdateDefaultAllow() {
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .defaultAllow)
    }

    func testHotReloadSwapsBehavior() {
        engine.updateRules([TestSupport.rule(id: 1, selectorValue: "ads.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .block(ruleId: 1))
        engine.updateRules([TestSupport.rule(id: 2, selectorValue: "tracker.example.com")])
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "ads.example.com")), .defaultAllow)
        XCTAssertEqual(engine.evaluate(TestSupport.flow(sni: "tracker.example.com")), .block(ruleId: 2))
    }

    func testMatchesIgnoresEnabledFlagAndAction() {
        let disabledAllow = TestSupport.rule(enabled: false, selectorValue: "ads.example.com", action: .allow)
        XCTAssertTrue(engine.matches(rule: disabledAllow, flow: TestSupport.flow(sni: "ads.example.com")))
        XCTAssertFalse(engine.matches(rule: disabledAllow, flow: TestSupport.flow(sni: "other.com")))
    }

    func testMatchesWorksWithoutUpdateRules() {
        XCTAssertTrue(engine.matches(
            rule: TestSupport.rule(selectorType: .app, selectorValue: "com.example.app"),
            flow: TestSupport.flow(appPackage: "com.example.app")
        ))
    }

    func testMatchesMalformedSelectorNeverThrows() {
        let bad = TestSupport.rule(selectorType: .ip, selectorValue: "///")
        XCTAssertFalse(engine.matches(rule: bad, flow: TestSupport.flow()))
    }
}
