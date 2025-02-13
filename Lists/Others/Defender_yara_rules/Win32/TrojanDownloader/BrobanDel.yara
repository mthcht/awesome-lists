rule TrojanDownloader_Win32_BrobanDel_A_2147690454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BrobanDel.A"
        threat_id = "2147690454"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uggc://" ascii //weight: 1
        $x_1_2 = "googleapis.com" ascii //weight: 1
        $x_1_3 = "6A71756572792E6A73" ascii //weight: 1
        $x_1_4 = "6974612E6A73" ascii //weight: 1
        $x_1_5 = "bit.ly/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_BrobanDel_A_2147690454_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BrobanDel.A"
        threat_id = "2147690454"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\numberchangerfirefox.xpi" ascii //weight: 1
        $x_1_2 = "6D73782E657865" ascii //weight: 1
        $x_1_3 = "Seu computador est" ascii //weight: 1
        $x_1_4 = "user_pref(\"extensions.autoDisableScopes\", 0);" ascii //weight: 1
        $x_1_5 = "636F6D6D656E74732E6A73" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

