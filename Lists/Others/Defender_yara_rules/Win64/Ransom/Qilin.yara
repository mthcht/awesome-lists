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

