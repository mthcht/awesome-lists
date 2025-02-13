rule Trojan_Win64_RedDelta_DA_2147779970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedDelta.DA!MTB"
        threat_id = "2147779970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedDelta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2ZsYXNodXBkYXRlZC5jb206ODAwMQ" ascii //weight: 1
        $x_1_2 = "ReflectiveLoader" ascii //weight: 1
        $x_1_3 = "BEGIN PUBLIC KEY" ascii //weight: 1
        $x_1_4 = "CRYPT_E_REVOKED" ascii //weight: 1
        $x_1_5 = "DbgUiStopDebugging" ascii //weight: 1
        $x_1_6 = "CLRLoader.exe" ascii //weight: 1
        $x_1_7 = "flach.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

