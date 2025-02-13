rule Trojan_Win64_T1098_AccountManipulation_A_2147846083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1098_AccountManipulation.A"
        threat_id = "2147846083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1098_AccountManipulation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "lsadump::dcshadow" wide //weight: 10
        $x_10_2 = "lsadump::dcsync" wide //weight: 10
        $x_10_3 = "lsadump::postzerologon" wide //weight: 10
        $x_10_4 = "lsadump::setntlm" wide //weight: 10
        $x_10_5 = "lsadump::changentlm" wide //weight: 10
        $x_10_6 = "misc::skeleton" wide //weight: 10
        $x_10_7 = "sid::modify" wide //weight: 10
        $x_10_8 = "sid::patch" wide //weight: 10
        $x_10_9 = "lsadump::zerologon" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

