rule Trojan_MSIL_AirStalk_A_2147956794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AirStalk.A!AMTB"
        threat_id = "2147956794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AirStalk"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Screenshot" ascii //weight: 1
        $x_1_2 = "api/mam/blobs/uploadblob" ascii //weight: 1
        $x_1_3 = "Killing old Chrome" ascii //weight: 1
        $x_1_4 = "Bookmarks_tmp.txt" ascii //weight: 1
        $x_1_5 = "AirWatchDebug_Log_tmp.txt" ascii //weight: 1
        $x_1_6 = "Win32_ComputerSystemProduct" ascii //weight: 1
        $x_1_7 = "Successfully dumped cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

