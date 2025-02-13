rule Trojan_Win32_TrickMailSearcher_A_2147753055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickMailSearcher.A!MTB"
        threat_id = "2147753055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickMailSearcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6c 46 69 6e 64 65 72 5f 78 [0-4] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "testMailFinder" ascii //weight: 1
        $x_1_3 = "TestMailFinder" ascii //weight: 1
        $x_1_4 = "end of URLs" ascii //weight: 1
        $x_1_5 = "URL in shared memory" ascii //weight: 1
        $x_1_6 = "End of mailCollector" ascii //weight: 1
        $x_1_7 = "\\LOG\\mailFinder.log" ascii //weight: 1
        $x_1_8 = "waiting command for module handle %i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

