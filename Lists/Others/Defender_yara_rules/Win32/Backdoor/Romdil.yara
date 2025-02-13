rule Backdoor_Win32_Romdil_A_2147573343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Romdil.gen!A"
        threat_id = "2147573343"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Romdil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fungsi2" ascii //weight: 1
        $x_1_2 = "Pergerakan" ascii //weight: 1
        $x_2_3 = "pr_Kerja_Trojan" ascii //weight: 2
        $x_2_4 = "Bunuh_Brontok_N_Krm_Email" ascii //weight: 2
        $x_2_5 = "Hancurkan_File" ascii //weight: 2
        $x_2_6 = "pr_Kopikan_Virus_KeSemua_Folder_Aktif" ascii //weight: 2
        $x_2_7 = "pr_Hapus_Brontok" ascii //weight: 2
        $x_2_8 = "pr_Setting_Walpaper_dan_regedit" ascii //weight: 2
        $x_2_9 = "Cetak_Kirim_mIRC" ascii //weight: 2
        $x_2_10 = "RomDev" ascii //weight: 2
        $x_2_11 = "UbahBrontok" ascii //weight: 2
        $x_2_12 = "\\Romatic-Devil.R.htm" wide //weight: 2
        $x_2_13 = "#Close CD Berhasil..." wide //weight: 2
        $x_2_14 = "/SHELL> Running Program berhasil..." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

