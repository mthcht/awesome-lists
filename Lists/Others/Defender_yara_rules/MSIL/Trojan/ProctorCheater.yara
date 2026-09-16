rule Trojan_MSIL_ProctorCheater_B_2147978264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ProctorCheater.B"
        threat_id = "2147978264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ProctorCheater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "target=Bluebook; using gentle path" ascii //weight: 1
        $x_1_2 = "hooks + interception + buddy + blockinput + wfp + dacl active" ascii //weight: 1
        $x_1_3 = "Bluebook is not running. Open Bluebook first, then click Attach" ascii //weight: 1
        $x_1_4 = "screenshot file never materialised" ascii //weight: 1
        $x_1_5 = "command send failed on both channels" ascii //weight: 1
        $x_1_6 = "[launcher] deep-analysis master switch ON" ascii //weight: 1
        $x_1_7 = "SECURELOCK_GEMINI_MODEL" ascii //weight: 1
        $x_1_8 = {73 63 72 65 65 6e 73 68 6f 74 20 63 6f 75 6c 64 6e 27 74 20 73 6f 6c 76 65 20 e2 80 94 20 65 73 63 61 6c 61 74 69 6e 67 20 74 6f 20 75 69 61}  //weight: 1, accuracy: High
        $x_1_9 = "uia fallback; asking gemini-" ascii //weight: 1
        $x_1_10 = "abandoned (toggled off during xml gemini)" ascii //weight: 1
        $x_1_11 = "You will receive a Digital SAT exam question from the Bluebook testing app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

