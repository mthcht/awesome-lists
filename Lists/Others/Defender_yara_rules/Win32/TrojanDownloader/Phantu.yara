rule TrojanDownloader_Win32_Phantu_A_2147581724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phantu.gen!A"
        threat_id = "2147581724"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phantu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFile" ascii //weight: 1
        $x_1_2 = "getURLS" ascii //weight: 1
        $x_1_3 = "Zombie_GetTypeInfoCount" ascii //weight: 1
        $x_1_4 = "Zombie_GetTypeInfo" ascii //weight: 1
        $x_1_5 = "tryin to reg window..." wide //weight: 1
        $x_1_6 = "about:blank-" wide //weight: 1
        $x_1_7 = "https-" wide //weight: 1
        $x_1_8 = "not ie, but: " wide //weight: 1
        $x_1_9 = "c.php?" wide //weight: 1
        $x_1_10 = "this is a contextual" wide //weight: 1
        $x_1_11 = "TotalLinks=" wide //weight: 1
        $x_1_12 = "LastLink=" wide //weight: 1
        $x_1_13 = "k.localsrv.net" wide //weight: 1
        $x_1_14 = "setting vpt" wide //weight: 1
        $x_1_15 = "do ac..............." wide //weight: 1
        $x_1_16 = "c.localsrv.net" wide //weight: 1
        $x_1_17 = "do close..............." wide //weight: 1
        $x_1_18 = "s.localsrv.net" wide //weight: 1
        $x_1_19 = "show normal..............." wide //weight: 1
        $x_1_20 = "try to pop aclink!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" wide //weight: 1
        $x_1_21 = "++++++IEObj_DocumentComplete-->" wide //weight: 1
        $x_1_22 = "Referer: " wide //weight: 1
        $x_1_23 = "new pop: " wide //weight: 1
        $x_1_24 = "pop vis..............." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (20 of ($x*))
}

rule TrojanDownloader_Win32_Phantu_B_2147641939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phantu.gen!B"
        threat_id = "2147641939"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phantu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "IN POP popURL" wide //weight: 3
        $x_2_2 = "frmPopper" ascii //weight: 2
        $x_2_3 = "CheckURL Error: " wide //weight: 2
        $x_2_4 = "\\popper.vbp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

