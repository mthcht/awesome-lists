rule Trojan_Win64_T1003_OsCredentialDumping_A_2147846084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1003_OsCredentialDumping.A"
        threat_id = "2147846084"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1003_OsCredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "lsadump::mbc" wide //weight: 10
        $x_10_2 = "lsadump::netsync" wide //weight: 10
        $x_10_3 = "lsadump::trust" wide //weight: 10
        $x_10_4 = "misc::aadcookie" wide //weight: 10
        $x_10_5 = "misc::addsid" wide //weight: 10
        $x_10_6 = "misc::shadowcopies" wide //weight: 10
        $x_10_7 = "misc::ngcsign" wide //weight: 10
        $x_10_8 = "misc::sccm" wide //weight: 10
        $x_10_9 = "sekurlsa::dpapi" wide //weight: 10
        $x_10_10 = "sekurlsa::dpapisystem" wide //weight: 10
        $x_10_11 = "sekurlsa::ekeys" wide //weight: 10
        $x_10_12 = "sekurlsa::logonpasswords" wide //weight: 10
        $x_10_13 = "sekurlsa::msv" wide //weight: 10
        $x_10_14 = "sekurlsa::trust" wide //weight: 10
        $x_10_15 = "sekurlsa::tspkg" wide //weight: 10
        $x_10_16 = "sekurlsa::wdigest" wide //weight: 10
        $x_10_17 = "token::list" wide //weight: 10
        $x_10_18 = "token::elevate" wide //weight: 10
        $x_10_19 = "ts::logonpasswords" wide //weight: 10
        $x_10_20 = "ts::mstsc" wide //weight: 10
        $x_10_21 = "lsadump::sam" wide //weight: 10
        $x_10_22 = "lsadump::secrets" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

