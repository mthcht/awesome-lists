rule Trojan_Win32_RustzExec_A_2147915429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustzExec.A!MTB"
        threat_id = "2147915429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustzExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "src\\client\\client.rs" ascii //weight: 1
        $x_1_2 = "src\\proxy.rs" ascii //weight: 1
        $x_1_3 = "src\\task\\download.rs" ascii //weight: 1
        $x_1_4 = "spawning" ascii //weight: 1
        $x_1_5 = "src\\task\\execute.rs" ascii //weight: 1
        $x_1_6 = {68 74 74 70 [0-16] 2e 63 72 65 70 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

