rule TrojanDownloader_AutoIt_Remerl_A_2147711609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AutoIt/Remerl.A!bit"
        threat_id = "2147711609"
        type = "TrojanDownloader"
        platform = "AutoIt: AutoIT scripts"
        family = "Remerl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If ProcessExists(\"avastui.exe\") Then Sleep(20000)" ascii //weight: 1
        $x_1_2 = "$path = \"542a49tpb3b73\"" ascii //weight: 1
        $x_1_3 = "$antibotkill = \"8792015\"" ascii //weight: 1
        $x_1_4 = "AdlibRegister(\"systemhide\", 500)" ascii //weight: 1
        $x_1_5 = "Local $hdownload = InetGet(\"replace-me-url\", $unicode_userprofile & \"\\\" & $random_download_name, 1, 1)" ascii //weight: 1
        $x_1_6 = "FileSetAttrib($unicode_userprofile & \"\\\" & $path & \"\\51281.vbs\", \"+SHR\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

