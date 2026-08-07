rule Trojan_Win32_AcrStealer_DB_2147975624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcrStealer.DB!MTB"
        threat_id = "2147975624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "================== HR Tool Alt" ascii //weight: 1
        $x_1_2 = "================ Finance Alt Tool (no -lm) ================" ascii //weight: 1
        $x_1_3 = "--- Black-Scholes option price (no libm) ---" ascii //weight: 1
        $x_1_4 = "--- Implied volatility (bisection) ---" ascii //weight: 1
        $x_1_5 = "--- Historical VaR / ES from returns file ---" ascii //weight: 1
        $x_1_6 = "--- Max drawdown from equity curve file ---" ascii //weight: 1
        $x_1_7 = "--- 2-asset minimum-variance weights ---" ascii //weight: 1
        $x_1_8 = "--- FX forward pricing (simple interest parity) ---" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

