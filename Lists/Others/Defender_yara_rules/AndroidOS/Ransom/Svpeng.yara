rule Ransom_AndroidOS_Svpeng_A_2147833752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Svpeng.A!MTB"
        threat_id = "2147833752"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".com/api/app.php" ascii //weight: 1
        $x_1_2 = "countphones" ascii //weight: 1
        $x_1_3 = "listphones" ascii //weight: 1
        $x_1_4 = "killProcess" ascii //weight: 1
        $x_1_5 = "com/brtohersoft/trnity" ascii //weight: 1
        $x_1_6 = {12 23 54 64 ?? ?? 54 65 ?? ?? 6e 40 ?? ?? 32 54 54 62 ?? ?? 71 10 ?? ?? 07 00 0c 03 6e 20 ?? ?? 32 00 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

