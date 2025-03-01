rule Trojan_Win64_Shellcoderunner_DA_2147921033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcoderunner.DA!MTB"
        threat_id = "2147921033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcoderunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d ac 24 00 02 00 00 48 8d 15 ?? ?? ?? ?? 52 48 8d 15 ?? ?? ?? ?? 52 c3 07 00 48 81 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d ac 24 00 02 00 00 48 8d 05 ?? ?? ?? ?? 50 55 48 89 e5 48 81 ec 07 00 48 81 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

