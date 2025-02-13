rule Ransom_Win32_Chaicha_2147729086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chaicha"
        threat_id = "2147729086"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaicha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "Your files, photos, documents, databases and other important files are encrypted and have the extension: .SAVEfiles" ascii //weight: 4
        $x_4_2 = "All your files, documents, photos, databases and other important files are encrypted and have the extension: .WHY" ascii //weight: 4
        $x_4_3 = "!!!SAVE_FILES_INFO!!!.txt" ascii //weight: 4
        $x_4_4 = "!!!WHY__MY__FILES__NOT__OPEN!!!.txt" ascii //weight: 4
        $x_4_5 = "BM-2cXonzj9ovn5qdX2MrwMK4j3qCquXBKo4h@bitmessage.ch" ascii //weight: 4
        $x_4_6 = "BM-2cUm1HG5NFf9fYMhPzLhjoBdXqde26iBm2@bitmessage.ch" ascii //weight: 4
        $x_1_7 = "After purchase you will start decrypt software" ascii //weight: 1
        $x_1_8 = "Only we can give you this key and only we can recover your files." ascii //weight: 1
        $x_1_9 = "you can send us a 1-3 any not very big encrypted files and we will send you back it in a original form FREE." ascii //weight: 1
        $x_1_10 = {50 72 69 63 65 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 24 ?? 30 30 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Chaicha_2147729086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chaicha"
        threat_id = "2147729086"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaicha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--Admin" wide //weight: 1
        $x_1_2 = "--ForNetRes" wide //weight: 1
        $x_1_3 = "--AutoStart" wide //weight: 1
        $x_1_4 = "--Service" wide //weight: 1
        $x_1_5 = "IsNotAutoStart" wide //weight: 1
        $x_1_6 = "IsAutoStart" wide //weight: 1
        $x_2_7 = "C:\\INTERNAL\\REMOTE.EXE" ascii //weight: 2
        $x_2_8 = "C:\\TEMP\\\\delself.bat" ascii //weight: 2
        $x_6_9 = "http://www.terranowwa.org/orgasmatron/get.php" ascii //weight: 6
        $x_6_10 = "http://www.terranowwa.org/syssvr.exe$run" ascii //weight: 6
        $x_6_11 = "http://www.terranowwa.org/systime.exe$run" ascii //weight: 6
        $x_10_12 = "--AutoStart x5I74v4h003xJ0iyhUfHQ8W6o0RDSicmSfg72KVA 6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0" wide //weight: 10
        $x_10_13 = "--ForNetRes x5I74v4h003xJ0iyhUfHQ8W6o0RDSicmSfg72KVA 6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0 IsNotAutoStart" wide //weight: 10
        $x_10_14 = "--Service 3980 x5I74v4h003xJ0iyhUfHQ8W6o0RDSicmSfg72KVA 6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0" wide //weight: 10
        $x_10_15 = "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}" ascii //weight: 10
        $x_10_16 = "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_6_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_6_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_6_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_6_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_6_*) and 2 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_6_*))) or
            ((4 of ($x_10_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_6_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

