rule Ransom_Win64_Qilin_B_2147917635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Qilin.B"
        threat_id = "2147917635"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Qilin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-DATA.txt" ascii //weight: 1
        $x_1_2 = "Encryption without notes" ascii //weight: 1
        $x_1_3 = "Skip encryption of network data" ascii //weight: 1
        $x_1_4 = "Sets the path to the file or directory to be encrypted" ascii //weight: 1
        $x_1_5 = "55736167653A20707365786563" ascii //weight: 1
        $x_1_6 = "[*.exe*.EXE*.DLL*.ini*.inf*.pol*.cmd*.ps1*.vbs*.bat*.pagefile.sys*" ascii //weight: 1
        $x_1_7 = "sqldocrtfxlsjpgjpegpnggifwebptiffpsdrawbmppdfdocxdocmdotxdotmodtxlsxxlsmxlt" ascii //weight: 1
        $x_1_8 = "%i in ('sc query state^= all ^| findstr /I ') do sc stop %i" ascii //weight: 1
        $x_1_9 = "| ForEach-Object { Stop-VM -Name $_.Name -Force -Confirm:$false" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_Win64_Qilin_A_2147960430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Qilin.A!AMTB"
        threat_id = "2147960430"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Qilin"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network has been penetrated by Qilin" ascii //weight: 1
        $x_1_2 = "Global\\QILIN_ENCRYPT" ascii //weight: 1
        $x_1_3 = "README_QILIN" ascii //weight: 1
        $x_1_4 = "All files have been encrypted by Qilin ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Qilin_MXL_2147963016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Qilin.MXL!MTB"
        threat_id = "2147963016"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Qilin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 d0 83 c2 01 48 83 c1 01 83 e0 1f 0f b6 44 04 50 32 41 ff f7 d0 c0 c0 04 88 41 ff 81 fa 00 02 00 00 75 dc}  //weight: 5, accuracy: High
        $x_1_2 = "Halo! File Anda baru saja tidak tersedia" ascii //weight: 1
        $x_1_3 = "SISTEM DIKOMPROMIKAN" ascii //weight: 1
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "DisableBehaviorMonitoring" ascii //weight: 1
        $x_1_6 = "encrypted.data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Qilin_FXL_2147963433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Qilin.FXL!MTB"
        threat_id = "2147963433"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Qilin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 3
        $x_3_2 = "All your documents, photos, databases" ascii //weight: 3
        $x_1_3 = "and backups have been locked" ascii //weight: 1
        $x_1_4 = "Find !!!_READ_ME_!!!.txt on your desktop" ascii //weight: 1
        $x_2_5 = "Do NOT delete or modify encrypted files" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

