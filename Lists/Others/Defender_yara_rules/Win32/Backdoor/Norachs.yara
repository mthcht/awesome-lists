rule Backdoor_Win32_Norachs_A_2147577566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Norachs.A"
        threat_id = "2147577566"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Norachs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5850505589E55753515231C0EB0EE8xxxxx01x83F802742285C074258B45103D0008000074433D01080000745BE8200000005A595B5FC9C21400E813" wide //weight: 1
        $x_1_2 = "modSocketMaster" ascii //weight: 1
        $x_1_3 = "vb4projectVb" ascii //weight: 1
        $x_1_4 = "cmSocket" ascii //weight: 1
        $x_1_5 = "RemoteDOS" ascii //weight: 1
        $x_5_6 = "\\wc.jpg" wide //weight: 5
        $x_5_7 = "\\WINSTART.bat" wide //weight: 5
        $x_5_8 = "\\temp.reg" wide //weight: 5
        $x_5_9 = "\\proc32.dll" wide //weight: 5
        $x_5_10 = "> Command Complete" wide //weight: 5
        $x_5_11 = "DRIVES|" wide //weight: 5
        $x_5_12 = "FREQ|" wide //weight: 5
        $x_5_13 = "nocompress|" wide //weight: 5
        $x_5_14 = "yplg|" wide //weight: 5
        $x_5_15 = "nplg|" wide //weight: 5
        $x_5_16 = "UFIN|" wide //weight: 5
        $x_2_17 = "Client_Server" wide //weight: 2
        $x_3_18 = "[ScrollLock]" wide //weight: 3
        $x_3_19 = "[NumLock]" wide //weight: 3
        $x_3_20 = "[Pause]" wide //weight: 3
        $x_3_21 = "[PageUp]" wide //weight: 3
        $x_3_22 = "[TAB]" wide //weight: 3
        $x_2_23 = "=dword:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((7 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((8 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((8 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((8 of ($x_5_*) and 5 of ($x_3_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((9 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((9 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((9 of ($x_5_*) and 4 of ($x_3_*))) or
            ((10 of ($x_5_*) and 5 of ($x_1_*))) or
            ((10 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((10 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((10 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((10 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((10 of ($x_5_*) and 2 of ($x_3_*))) or
            ((11 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Norachs_B_2147577965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Norachs.B"
        threat_id = "2147577965"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Norachs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "acceptpw|" wide //weight: 1
        $x_1_2 = "cliptext|" wide //weight: 1
        $x_1_3 = "cmessage|" wide //weight: 1
        $x_1_4 = "extensionplease|" wide //weight: 1
        $x_1_5 = "homepage|" wide //weight: 1
        $x_1_6 = "imquestion|" wide //weight: 1
        $x_1_7 = "kcaption|" wide //weight: 1
        $x_1_8 = "keylog|" wide //weight: 1
        $x_1_9 = "mmbody|" wide //weight: 1
        $x_1_10 = "mmbuttons|" wide //weight: 1
        $x_1_11 = "pwordreject|" wide //weight: 1
        $x_1_12 = "ycoord|" wide //weight: 1
        $x_1_13 = "fopencddoor" wide //weight: 1
        $x_1_14 = "fclosecddoor" wide //weight: 1
        $x_1_15 = "serverremove" wide //weight: 1
        $x_1_16 = "serverreset" wide //weight: 1
        $x_1_17 = "compshut" wide //weight: 1
        $x_1_18 = "complogoff" wide //weight: 1
        $x_1_19 = "mfappbomb" wide //weight: 1
        $x_1_20 = "mfbeepon" wide //weight: 1
        $x_1_21 = "mfbeepoff" wide //weight: 1
        $x_1_22 = "mftrashon" wide //weight: 1
        $x_1_23 = "mftrashoff" wide //weight: 1
        $x_1_24 = "mfcdloop" wide //weight: 1
        $x_1_25 = "mficonshide" wide //weight: 1
        $x_1_26 = "floodcomp" wide //weight: 1
        $x_1_27 = "mfeatmem" wide //weight: 1
        $x_1_28 = "fblackon" wide //weight: 1
        $x_1_29 = "fblackoff" wide //weight: 1
        $x_1_30 = "fblockion" wide //weight: 1
        $x_1_31 = "fblockioff" wide //weight: 1
        $x_1_32 = "fhidetask" wide //weight: 1
        $x_1_33 = "fshowtask" wide //weight: 1
        $x_1_34 = "mfhidedesktop" wide //weight: 1
        $x_1_35 = "mfshowdesktop" wide //weight: 1
        $x_1_36 = "ffbion" wide //weight: 1
        $x_1_37 = "mfreeze" wide //weight: 1
        $x_1_38 = "munfreeze" wide //weight: 1
        $x_1_39 = "startmenutext" wide //weight: 1
        $x_1_40 = "<'Complete'>" wide //weight: 1
        $x_1_41 = "[Current Window: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (25 of ($x*))
}

rule Backdoor_Win32_Norachs_C_2147581591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Norachs.C"
        threat_id = "2147581591"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Norachs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0001{" wide //weight: 1
        $x_1_2 = "}0001" wide //weight: 1
        $x_1_3 = "0002{" wide //weight: 1
        $x_1_4 = "}0002" wide //weight: 1
        $x_1_5 = "0003{" wide //weight: 1
        $x_1_6 = "}0003" wide //weight: 1
        $x_1_7 = "dijpg.dll" wide //weight: 1
        $x_1_8 = "c:\\Progra~1\\Ares\\MyShar~1\\VisualBasic.exe" wide //weight: 1
        $x_1_9 = "c:\\Docume~1\\Owner\\Shared\\VisualBasic.exe" wide //weight: 1
        $x_1_10 = "c:\\Docume~1\\Owner\\Mydocu~1\\Morphe~1\\VisualBasic.exe" wide //weight: 1
        $x_1_11 = "c:\\MyDown~1\\VisualBasic.exe" wide //weight: 1
        $x_1_12 = "c:\\Docume~1\\Owner\\Mydocu~1\\MyMusi~1\\iMesh\\VisualBasic.exe" wide //weight: 1
        $x_1_13 = "c:\\Progra~1\\eMule\\Incomming\\VisualBasic.exe" wide //weight: 1
        $x_1_14 = "c:\\Progra~1\\Shareaza\\Collections\\VisualBasic.exe" wide //weight: 1
        $x_1_15 = "c:\\Progra~1\\Shareaza\\Downloads\\VisualBasic.exe" wide //weight: 1
        $x_1_16 = "c:\\Progra~1\\Gluz\\Shared\\VisualBasic.exe" wide //weight: 1
        $x_1_17 = "set CDAudio door open" wide //weight: 1
        $x_1_18 = "set CDAudio door closed" wide //weight: 1
        $x_1_19 = "Problem Downloading File! Check the URL And Save Path." wide //weight: 1
        $x_1_20 = "File Downloaded And Saved To Location specified!" wide //weight: 1
        $x_1_21 = "DOWNS|" wide //weight: 1
        $x_1_22 = "READYUP|" wide //weight: 1
        $x_1_23 = "WebcamCapture" wide //weight: 1
        $x_1_24 = "READYCAM|" wide //weight: 1
        $x_1_25 = "READY|" wide //weight: 1
        $x_1_26 = "FREQ|" wide //weight: 1
        $x_1_27 = "FREQCAM|" wide //weight: 1
        $x_1_28 = "READYFDOWN|" wide //weight: 1
        $x_1_29 = "REQFDOWN" wide //weight: 1
        $x_1_30 = "FREQFDOWN|" wide //weight: 1
        $x_1_31 = "SENDFDOWN" wide //weight: 1
        $x_1_32 = "SENDUP|" wide //weight: 1
        $x_1_33 = "DEAD|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (21 of ($x*))
}

rule Backdoor_Win32_Norachs_D_2147583034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Norachs.D"
        threat_id = "2147583034"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Norachs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 53 6f 63 6b 65 74 4d 61 73 74 65 72 00 00 00 4d 6f 64 75 6c 65 31 00 44 4f 53 4f 75 74 70 75 74 73 00 00 4d 61 69 6e 46 6f 72 6d 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 4d 98 0f 94 c0 f7 d8 66 89 85 50 ff ff ff e8 09 cf fc ff 66 39 b5 50 ff ff ff 74 75 8b 03 53 ff 90 04 03 00 00 50 8d 45 98 50 e8 0b cf fc ff 83 ec}  //weight: 1, accuracy: High
        $x_1_3 = {10 8d b5 74 ff ff ff 8b fc c7 85 7c ff ff ff 04 00 02 80 c7 85 74 ff ff ff 0a 00 00 00 8b 08 a5 a5 a5 68 3c fb 40 00 50 89 85 58 ff ff ff a5 ff 91 ec}  //weight: 1, accuracy: High
        $x_1_4 = {01 00 00 85 c0 db e2 7d 16 68 ec 01 00 00 68 28 ee 40 00 ff b5 58 ff ff ff 50 e8 a6 ce fc ff 8d 4d 98 e8 92 ce fc ff 33 f6 bf 28 ee 40 00 8b 03 53 ff}  //weight: 1, accuracy: High
        $x_1_5 = {90 04 03 00 00 50 8d 45 98 50 e8 96 ce fc ff 8b 08 56 50 89 85 58 ff ff ff ff 91 e4 00 00 00 3b c6 db e2 7d 12 68 e4 00 00 00 57 ff b5 58 ff ff ff 50}  //weight: 1, accuracy: High
        $x_1_6 = {e8 5c ce fc ff 8d 4d 98 e8 48 ce fc ff 8b 03 53 ff 90 04 03 00 00 50 8d 45 98 50 e8 53 ce fc ff 8b 08 8d 95 60 ff ff ff 52 50 89 85 58 ff ff ff ff 91}  //weight: 1, accuracy: High
        $x_1_7 = {e0 00 00 00 3b c6 db e2 7d 12 68 e0 00 00 00 57 ff b5 58 ff ff ff 50 e8 13 ce fc ff 66 8b 85 60 ff ff ff 8d 95 74 ff ff ff 8d 4d c8 66 89 85 7c ff ff}  //weight: 1, accuracy: High
        $x_1_8 = {ff c7 85 74 ff ff ff 02 00 00 00 e8 d9 cf fc ff 8d 4d 98 e8 d9 cd fc ff 8b 03 53 ff 90 04 03 00 00 50 8d 45 98 50 e8 e4 cd fc ff 8b 08 8d 55 a0 52 50}  //weight: 1, accuracy: High
        $x_1_9 = {89 85 58 ff ff ff ff 91 f8 00 00 00 3b c6 db e2 7d 12 68 f8 00 00 00 57 ff b5 58 ff ff ff 50 e8 a7 cd fc ff ff 75 a0 68 3c fb 40 00 e8 2c cc fc ff 8b}  //weight: 1, accuracy: High
        $x_1_10 = {f8 8d 4d a0 f7 df 1b ff 47 f7 df e8 83 cd fc ff 8d 4d 98 e8 75 cd fc ff 66 3b fe 74 4b 83 ec 10 8d b5 74 ff ff ff 8b fc c7 85 7c ff ff ff 4c fb 40 00}  //weight: 1, accuracy: High
        $x_1_11 = {c7 85 74 ff ff ff 08 00 00 00 8b 03 a5 a5 a5 6a 01 68 1e 00 03 60 53 a5 ff 90 0c 03 00 00 50 8d 45 98 50 e8 51 cd fc ff 50 e8 19 cf fc ff 83 c4 1c e9}  //weight: 1, accuracy: High
        $x_1_12 = {71 02 00 00 8b 03 53 ff 90 a8 07 00 00 8d 85 60 ff ff ff 89 b5 60 ff ff ff 50 8d 45 dc 56 50 e8 3b cd fc ff 50 8d 45 a8 50 e8 31 cd fc ff 50 e8 63 1d}  //weight: 1, accuracy: High
        $x_1_13 = {fd ff e8 d8 cc fc ff 8b 03 53 ff 90 ac 07 00 00 39 35 74 9c 43 00 75 0f 68 74 9c 43 00 68 c8 bb 40 00 e8 a6 cc fc ff 8b 3d 74 9c 43 00 8d 4d 98 51 57}  //weight: 1, accuracy: High
        $x_1_14 = {8b 07 ff 50 1c 3b c6 db e2 7d 11 bb b8 bb 40 00 6a 1c 53 57 50 e8 b7 cc fc ff eb 05 bb b8 bb 40 00 8d 55 94 8d b5 74 ff ff ff 52 c7 85 7c ff ff ff 04}  //weight: 1, accuracy: High
        $x_1_15 = {00 02 80 83 ec 10 c7 85 74 ff ff ff 0a 00 00 00 8b fc 8b 45 98 a5 8b 08 50 a5 a5 89 85 50 ff ff ff a5 ff 51 54 85 c0 db e2 7d 13 6a 54 68 b0 fa 40 00}  //weight: 1, accuracy: High
        $x_1_16 = {ff b5 50 ff ff ff 50 e8 61 cc fc ff 8b 45 94 83 ec 10 8d 75 84 8b fc 89 45 8c c7 45 84 09 00 00 00 a5 a5 83 65 94 00 8d 45 b8 a5 68 5c fb 40 00 50 a5}  //weight: 1, accuracy: High
        $x_1_17 = {e8 ac ce fc ff 8d 4d 98 e8 22 cc fc ff 8d 4d 84 e8 d2 cb fc ff 6a 00 8d 45 b8 68 6c fb 40 00 50 8d 45 84 50 e8 74 cd fc ff 83 c4 10 83 3d 74 9c 43 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 75 0f 68 74 9c 43 00 68 c8 bb 40 00 e8 c1 cb fc ff 8b 35 74 9c 43 00 68 f0 f1 40 00 8d 45 84 68 78 fb 40 00 8b 3e 50 e8 46 cb fc ff 50 8d 45 98 50}  //weight: 1, accuracy: High
        $x_1_19 = {e8 e4 cb fc ff 50 56 ff 57 40 85 c0 db e2 7d 0a 6a 40 53 56 50 e8 bd cb fc ff 8d 4d 98 e8 a9 cb fc ff 8d 4d 84 e8 59 cb fc ff e8 58 ca fc ff 83 8d 5c}  //weight: 1, accuracy: High
        $x_1_20 = {ff ff ff ff 8d 85 5c ff ff ff 50 e8 eb ba fd ff 8b d0 8d 4d a0 e8 a3 cb fc ff be 8c fb 40 00 50 56 e8 0d cb fc ff 8b d0 8d 4d 9c e8 8d cb fc ff 8d 45}  //weight: 1, accuracy: High
        $x_1_21 = {9c 50 ff 75 0c e8 d3 e8 fe ff 8d 45 9c 50 8d 45 a0 50 6a 02 e8 18 cb fc ff 83 8d 5c ff ff ff ff 83 c4 0c 8d 85 5c ff ff ff 50 e8 9a ba fd ff 8b d0 8d}  //weight: 1, accuracy: High
        $x_1_22 = {4d a0 e8 52 cb fc ff 50 56 e8 c1 ca fc ff 8b d0 8d 4d d8 e8 41 cb fc ff 8d 4d a0 e8 1b cb fc ff e8 cc c9 fc ff e8 c7 c9 fc ff 83 3d 74 9c 43 00 00 75}  //weight: 1, accuracy: High
        $x_1_23 = {0f 68 74 9c 43 00 68 c8 bb 40 00 e8 c9 ca fc ff 8b 35 74 9c 43 00 8d 4d 98 51 56 8b 06 ff 50 1c 85 c0 db e2 7d 0a 6a 1c 53 56 50 e8 df ca fc ff 8b 45}  //weight: 1, accuracy: High
        $x_1_24 = {98 50 8b f0 8b 08 ff 51 50 85 c0 db e2 7d 0e 6a 50 68 b0 fa 40 00 56 50 e8 c0 ca fc ff 8d 4d 98 e8 ac ca fc ff 68 da 75 43 00 eb 38 f6 45 fc 04 74 08}  //weight: 1, accuracy: High
        $x_1_25 = {8d 4d d8 e8 9d ca fc ff 8d 45 9c 50 8d 45 a0 50 6a 02 e8 52 ca fc ff 8d 45 94 50 8d 45 98 50 6a 02 e8 3b cc fc ff 83 c4 18 8d 4d 84 e8 26 ca fc ff c3}  //weight: 1, accuracy: High
        $x_1_26 = {8d 4d dc e8 1d ca fc ff 8d 4d c8 e8 15 ca fc ff 8d 4d b8 e8 0d ca fc ff 8d 4d a8 e8 05 ca fc ff 8d 4d a4 e8 45 ca fc ff c3 8b 45 08 50 8b 08 ff 51 08}  //weight: 1, accuracy: High
        $x_1_27 = {8b 45 10 8b 4d d8 89 08 8b 45 fc 8b 4d ec 5f 5e 64 89 0d 00 00 00 00 5b c9 c2 0c 00 cc 9e 9e 9e 9e}  //weight: 1, accuracy: High
        $x_1_28 = "C*\\AC:\\Documents and Settings\\chris\\Desktop\\Omerta 1.3 Programming\\Server\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

