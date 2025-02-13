rule Trojan_MSIL_LovGate_KWZ_2147796923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LovGate.KWZ!MTB"
        threat_id = "2147796923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LovGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JGJlc3Q2NGNvZGUgPSAiSzBBYnpOWExnRXpOMEFUTWdRbmN2QlhMZ0FqTHc" wide //weight: 1
        $x_1_2 = "dm9rZS1FeHByZXNzaW9uICRMb2FkQ29kZQ==" wide //weight: 1
        $x_1_3 = "VOQmRuVEIxRVJCQlRRMzFVUUpkVVF4RVVRYUZVVkVG" wide //weight: 1
        $x_1_4 = "spzzcify thzz -zzxtract" ascii //weight: 1
        $x_1_5 = "-whatt" ascii //weight: 1
        $x_1_6 = "-extdummt" ascii //weight: 1
        $x_1_7 = "out-string" ascii //weight: 1
        $x_1_8 = "CREDUI_INFO" ascii //weight: 1
        $x_1_9 = "SERVER_CREDENTIAL" ascii //weight: 1
        $x_1_10 = "USERNAME_TARGET_CREDENTIALS" ascii //weight: 1
        $x_1_11 = "PowerShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

