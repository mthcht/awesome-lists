rule HackTool_Win32_Rclone_SC_2147927210_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Rclone.SC"
        threat_id = "2147927210"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rclone"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " copy " wide //weight: 1
        $x_1_2 = " --ignore-existing " wide //weight: 1
        $x_1_3 = " --config " wide //weight: 1
        $x_1_4 = " --multi-thread-streams " wide //weight: 1
        $x_1_5 = " --transfers " wide //weight: 1
        $x_1_6 = " --auto-confirm " wide //weight: 1
        $x_1_7 = " --max-size " wide //weight: 1
        $x_1_8 = " --max-age " wide //weight: 1
        $x_1_9 = " --bwlimit" wide //weight: 1
        $x_1_10 = " mega:" wide //weight: 1
        $x_30_11 = " --exclude \"*{psd,mov,fit,fil,mp4,mp3,mov,mdb,iso,exe,dll,frx,psr,msi,vdi,pst,db,iso,db,pkg,exe,sav,asd,tmp,xar,vhd}" wide //weight: 30
        $x_30_12 = " --exclude \"*.{psd,7z,rar,zip,mov,pst,fit,fil,mp4,mov,mdb,iso,exe,dll}" wide //weight: 30
        $x_15_13 = {20 00 2d 00 2d 00 65 00 78 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 69 00 73 00 6f 00}  //weight: 15, accuracy: Low
        $x_15_14 = {20 00 2d 00 2d 00 65 00 78 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 6d 00 70 00 33 00}  //weight: 15, accuracy: Low
        $x_15_15 = {20 00 2d 00 2d 00 65 00 78 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 69 00 6e 00 63 00}  //weight: 15, accuracy: Low
        $x_15_16 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 64 00 6f 00 63 00}  //weight: 15, accuracy: Low
        $x_15_17 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 70 00 64 00 66 00}  //weight: 15, accuracy: Low
        $x_15_18 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 63 00 73 00 76 00}  //weight: 15, accuracy: Low
        $x_15_19 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 78 00 6c 00 73 00 78 00}  //weight: 15, accuracy: Low
        $x_30_20 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00}  //weight: 30, accuracy: Low
        $x_15_21 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 70 00 70 00 74 00}  //weight: 15, accuracy: Low
        $x_15_22 = {20 00 2d 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 [0-32] 6d 00 73 00 67 00}  //weight: 15, accuracy: Low
        $n_200_23 = "aws.exe" wide //weight: -200
        $n_200_24 = "--user-agent \"isv|rclone.org|rclone/1.55.1" wide //weight: -200
        $n_200_25 = "\\gsl\\filesync:" wide //weight: -200
        $n_200_26 = "--log-file" wide //weight: -200
        $n_200_27 = "therapeutic guidelines" wide //weight: -200
        $n_200_28 = "ginesysfilestorage" wide //weight: -200
        $n_200_29 = "dellfiletransferutil.exe" wide //weight: -200
        $n_200_30 = "aegis\\hbrclient\\" wide //weight: -200
        $n_200_31 = "\\games vr\\armgddn browser\\ag.exe" wide //weight: -200
        $n_200_32 = "rsymdrv.exe" wide //weight: -200
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_15_*) and 2 of ($x_1_*))) or
            ((3 of ($x_15_*))) or
            ((1 of ($x_30_*) and 2 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_15_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

