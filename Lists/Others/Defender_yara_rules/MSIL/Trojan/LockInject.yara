rule Trojan_MSIL_LockInject_NVD_2147819831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LockInject.NVD!MTB"
        threat_id = "2147819831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 b7 00 00 70 a2 25 17 72 bb 00 00 70 a2 25 18 72 bf 00 00 70 a2 25 19 72 c3 00 00 70 a2 25 1a 72 bb 00 00 70 a2 25 1b 72 c7 00 00 70 a2 25 1c}  //weight: 1, accuracy: High
        $x_1_2 = {72 cb 00 00 70 a2 25 1d 72 cf 00 00 70 a2 25 1e 72 d3 00 00 70 a2 25 1f 09 72 d7 00 00 70 a2 25 1f 0a 72 db 00 00 70 a2 25 1f 0b 72 db 00 00 70}  //weight: 1, accuracy: High
        $x_1_3 = "72f06fbe90c8" ascii //weight: 1
        $x_1_4 = "kidLock.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

