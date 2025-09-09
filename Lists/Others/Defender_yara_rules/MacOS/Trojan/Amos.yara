rule Trojan_MacOS_Amos_A_2147845893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.A!MTB"
        threat_id = "2147845893"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".GrabFirefox" ascii //weight: 1
        $x_1_2 = ".FileGrabber" ascii //weight: 1
        $x_1_3 = ".GrabWallets" ascii //weight: 1
        $x_1_4 = "main.keychain_extract" ascii //weight: 1
        $x_1_5 = "main.sendlog" ascii //weight: 1
        $x_1_6 = "/Desktop/amos builds/Source AMOS/conf.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_D_2147852515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.D!MTB"
        threat_id = "2147852515"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 ec 02 00 00 e8 6a 28 00 00 e8 3f 2d 00 00 e8 7e 30 00 00 e8 a4 37 00 00 e8 ad 40 00 00 48 8d 35 bd 0f 01 00 48 8d 15 f3 79 01 00 48 8d 9d 78 ff ff ff 48 89 df}  //weight: 1, accuracy: High
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk" ascii //weight: 1
        $x_1_3 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_4 = "/FileGrabber/" ascii //weight: 1
        $x_1_5 = "Host: amos-malware.ru" ascii //weight: 1
        $x_1_6 = "POST /sendlog HTTP/1.1" ascii //weight: 1
        $x_1_7 = "activateIgnoringOtherApps:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MacOS_Amos_E_2147892920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.E!MTB"
        threat_id = "2147892920"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 63 6f 6e 66 69 67 2e 76 64 66 00 53 74 65 61 6d 2f 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 53 74 65 61 6d 2f 63 6f 6e 66 69 67 2e 76 64 66}  //weight: 1, accuracy: High
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
        $x_1_3 = "deskwallets/atomic/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_F_2147893550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.F!MTB"
        threat_id = "2147893550"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deskwallets/Exodus/" ascii //weight: 1
        $x_1_2 = "FileGrabber/NoteStore.sqlite" ascii //weight: 1
        $x_1_3 = "/.config/filezilla/recentservers.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_N_2147894942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.N!MTB"
        threat_id = "2147894942"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Please enter your password" ascii //weight: 1
        $x_1_2 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_3 = "/dev/null find-generic-password -ga 'chrome'" ascii //weight: 1
        $x_1_4 = "/filegrabber/" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-21] 2f 73 65 6e 64 6c 6f 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_Amos_L_2147899672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.L!MTB"
        threat_id = "2147899672"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "post /sendlog http/1.1" ascii //weight: 1
        $x_1_2 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_3 = "find-generic-password -ga 'chrome" ascii //weight: 1
        $x_1_4 = "please enter your password" ascii //weight: 1
        $x_1_5 = "activateignoringotherapps:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_B_2147903370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.B!MTB"
        threat_id = "2147903370"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 69 69 38 eb 03 45 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 41 00 f1 41 ff ff 54 97 00 00 b0 f7 62 0e 91 e8 3e 40 39 09 1d 00 13 ea 02 40 f9 3f 01 00 71 55 b1 88 9a}  //weight: 5, accuracy: High
        $x_5_2 = {0a 69 69 38 ab 03 59 38 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 39 00 f1 41 ff ff 54 d6 00 00 d0 d6 a2 1e 91 d9 2f 8c 52 59 02 a0 72 c8 5e 40 39 09 1d 00 13 ca 06 40 f9 3f 01 00 71 54 b1 88 9a e0 03 13 aa}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_Amos_C_2147903379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.C!MTB"
        threat_id = "2147903379"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 69 69 38 eb 83 40 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 55 00 f1 41 ff ff 54 68 00 00 d0 08 61 0d 91 09 3d 40 39 2a 1d 00 13 08 01 40 f9 5f 01 00 71 15 b1 89 9a e0 03 13 aa}  //weight: 5, accuracy: High
        $x_5_2 = {49 29 dc 49 ff c4 0f 84 df fe ff ff 4c 89 f7 44 89 fe 4c 89 e2 e8 b9 e4 00 00 48 85 c0 0f 84 c8 fe ff ff 49 89 c6 48 89 c7 48 8d b5 51 ff ff ff 48 89 da e8 a1 e4 00 00 85 c0 0f 84 db 00 00 00 49 ff c6 4d 89 ec 4d 29 f4 49 39 dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_Amos_P_2147903498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.P!MTB"
        threat_id = "2147903498"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'chrome' | awk '{print $2}'" ascii //weight: 1
        $x_1_3 = "osascript -e 'tell application \"Terminal\" to close first window' & exit" ascii //weight: 1
        $x_1_4 = "/Library/Cookies/Cookies.binarycookies" ascii //weight: 1
        $x_1_5 = "osascript -e 'set destinationFolderPath to (path to home folder as text)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_G_2147904437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.G!MTB"
        threat_id = "2147904437"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/.walletwasabi/client/Wallets/" ascii //weight: 1
        $x_1_2 = "AMOS steals your passwords" ascii //weight: 1
        $x_1_3 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_H_2147907308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.H!MTB"
        threat_id = "2147907308"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 31 4d 89 f4 49 83 cc 0f 49 8d 7c 24 01 e8 f2 3a 00 00 48 89 43 10 49 83 c4 02 4c 89 23 4c 89 73 08 48 89 c3 48 89 df 4c 89 fe 4c 89 f2 e8 92 3b 00 00 42 c6 04 33 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 34 0f 57 c0 48 8b 51 f8 49 89 57 f8 0f 10 49 e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 41 e8 48 c7 41 f8 00 00 00 00 48 8d 51 e8 48 89 d1 48 39 c2 75 d3 4c 89 7d e0 48 8d 7d b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_I_2147910254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.I!MTB"
        threat_id = "2147910254"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 4d b8 30 4c 05 b8 48 ff c0 48 83 f8 03 75 f0 44 0f b6 ad 58 ff ff ff 44 89 eb 80 e3 01 74 52 4c 8b ad 60 ff ff ff eb 4c}  //weight: 2, accuracy: High
        $x_2_2 = {8a 8d 68 ff ff ff 30 8c 05 68 ff ff ff 48 ff c0 48 83 f8 03 75 ea 0f b6 1a f6 c3 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_M_2147912572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.M!MTB"
        threat_id = "2147912572"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 db 74 0c 48 ff cb 48 ff c7 41 8a 14 37 eb 04 31 d2 31 db 88 54 35 e5 48 ff c6 48 83 fe 03 75 de}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 83 e1 0f 8a 8c 0d 20 ff ff ff 41 30 0c 06 48 ff c0 49 39 c4 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_K_2147913315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.K!MTB"
        threat_id = "2147913315"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 83 01 d1 fa 67 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 f3 03 08 aa 1f 7d 00 a9 1f 09 00 f9 08 5c 40 39 09 1d 00 13 0a 2c 40 a9 3f 01 00 71 56 b1 80 9a 68 b1 88 9a e8 0a 00 b4}  //weight: 1, accuracy: High
        $x_1_2 = {15 00 80 d2 e8 37 40 39 09 7d 02 53 e9 27 00 39 e9 3b 40 39 2a 7d 04 53 0a 05 1c 33 ea 2b 00 39 e8 3f 40 39 0a 7d 06 53 2a 0d 1e 33 ea 2f 00 39 08 15 00 12 e8 33 00 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_S_2147913439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.S!MTB"
        threat_id = "2147913439"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 e6 19 02 00 89 c1 44 29 f9 31 db 48 83 f8 01 19 db 08 cb 0f be 75 d6 4c 89 ff}  //weight: 2, accuracy: High
        $x_2_2 = {48 8b 05 9a 21 02 00 48 8b 00 48 3b 45 d0 75 31 31 c0 48 83 c4 78 5b 41 5c 41 5d 41 5e 41 5f 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_Q_2147913718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.Q!MTB"
        threat_id = "2147913718"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 49 89 fe bf 10 00 00 00 e8 90 45 00 00 48 89 c3 48 89 c7 4c 89 f6 e8 2e 00 00 00 48 8b 35 5f 79 00 00 48 8b 15 08 79 00 00 48 89 df e8 90 45 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb e8 4a 44 00 00 48 8b 05 53 79 00 00 48 83 c0 10 48 89 03 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_R_2147914111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.R!MTB"
        threat_id = "2147914111"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 45 84 48 83 f8 0f 0f 83 25 00 00 00 48 8b 85 58 ff ff ff 48 63 4d 84 8a 54 0d e2 48 63 4d 84 88 54 08 0a 8b 45 84 83 c0 01 89 45 84}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 b0 ee ff ff 48 63 8d 9c ee ff ff 0f be 04 08 48 8b 8d a0 ee ff ff 8b 09 83 c1 04 31 c8 88 c2 48 8b 85 b0 ee ff ff 48 63 8d 9c ee ff ff 88 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_U_2147914112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.U!MTB"
        threat_id = "2147914112"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d d0 30 4c 05 d0 48 ff c0 48 83 f8 04 75 ?? 44 0f b6 23 41 f6 c4 01 48 89 7d c8 74 ?? 4c 8b 73 10}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 88 d2 ff ff 48 85 c0 0f ?? ?? ?? ?? ?? f3 48 0f 2a c0 e9 ?? ?? ?? ?? 4c 39 f1 72 ?? 48 89 c8 31 d2 49 f7 f6 48 89 d1 48 8b 85 70 d2 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_V_2147915262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.V!MTB"
        threat_id = "2147915262"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 c0 e8 06 c0 e1 02 08 c1 80 e1 3f 88 4d d3 4d 63 f7 45 31 e4}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 85 08 fe ff ff 32 6e 6a 01 58 48 83 f8 0b 74 12 8a 8d 00 fe ff ff 30 8c 05 00 fe ff ff 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_X_2147915882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.X!MTB"
        threat_id = "2147915882"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 1c 18 4e 10 3c 18 4e 41 02 00 b0 24 f8 c1 3d e4 17 80 3d 04 44 e4 6e 01 00 66 9e 42 02 00 b0 40 00 c2 3d e0 0b 80 3d 20 44 e0 6e 02 3c 18 4e 4e 1c 40 b3}  //weight: 1, accuracy: High
        $x_1_2 = {b5 73 1a 38 15 9c 68 d3 b5 de 70 d3 b6 ea 00 52 b6 63 1a 38 56 bc 68 d3 82 0c 80 52 c2 02 02 4a a2 53 1a 38 02 bc 70 d3 57 9c 60 d3 e2 02 0e 4a a2 43 1a 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_W_2147915943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.W!MTB"
        threat_id = "2147915943"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 4c 02 02 48 83 c0 02 0f b6 4c 18 01 32 0d 85 57 00 00 f6 85 60 fd ff ff 01 4c 89 ea 74 ?? 48 8b 95 70 fd ff ff 88 4c 02 01 48 3d ae 2d 00 00 74 ?? 0f b6 4c 18 02 32 0d 5b 57 00 00 f6 85 60 fd ff ff 01 4c 89 ea}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 4e 78 be 01 00 00 00 48 89 d7 4c 89 fa e8 f7 07 00 00 48 89 c1 b8 ff ff ff ff 4c 39 f9 0f 85 ?? ?? ?? ?? 4d 89 6e 30 4d 89 6e 28 4d 89 66 38 31 c0 83 fb ff 0f 45 c3 e9 1e ?? ?? ?? 89 5d bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_Z_2147917120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.Z!MTB"
        threat_id = "2147917120"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 7f 40 39 09 1d 00 13 eb ab 40 a9 3f 01 00 71 53 b1 88 9a 74 b1 94 9a 68 06 00 91 1f 41 00 b1 22 07 00 54 1f 5d 00 f1 a2 00 00 54 f5 83 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {e8 3f c1 39 08 ff ff 36 e0 1f 40 f9 4c 00 00 94 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 ff 03 02 91 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_Y_2147917132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.Y!MTB"
        threat_id = "2147917132"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d6 48 c1 ee 3e 48 31 d6 49 0f af f7 48 01 ce 48 ff ce 48 89 b4 cd a8 ef ff ff 48 81 f9 38 01 00 00 74 ?? ?? ?? ?? ?? 48 89 f7 48 c1 ef 3e 48 31 f7 49 0f af ff 48 01 fa 48 01 cf 48 89 bc cd b0 ef ff ff 48 83 c0 02 48 83 c1 02}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 48 c1 ea 1c 81 e2 00 ff 00 00 48 09 ca 48 89 c1 48 c1 e9 18 81 e1 00 00 ff 00 48 09 d1 48 89 c2 48 c1 ea 14 81 e2 00 00 00 ff 48 09 ca 48 89 c1 48 c1 e9 10 49 b8 00 00 00 00 ff 00 00 00 4c 21 c1 48 89 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AD_2147917134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AD!MTB"
        threat_id = "2147917134"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 6b 00 b9 28 00 80 52 29 6b 68 38 ea a3 41 39 29 01 0a 4a 29 6b 28 38 08 05 00 91 1f 11 00 f1 41 ?? ?? ?? e0 43 01 91 e1 13 40 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f7 03 02 aa f6 03 01 aa f4 03 00 aa 13 80 06 91 15 20 00 91 88 00 00 d0 08 e1 04 91 09 61 00 91 09 00 00 f9 08 01 01 91 08 d0 00 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AB_2147917785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AB!MTB"
        threat_id = "2147917785"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 06 40 f9 9f 02 15 eb 68 ?? ?? ?? 02 ?? ?? ?? a0 02 67 9e 00 58 20 0e 00 38 30 2e 08 00 26 1e 69 0e 40 f9 20 01 23 9e 61 22 40 bd 00 18 21 1e 00 00 29 9e bf 0e 00 f1 02 29 41 fa 69 ?? ?? ?? 19 04 00 94}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 00 aa 28 04 00 f1 61 ?? ?? ?? 54 00 80 52 07 ?? ?? ?? f4 03 01 aa 3f 00 08 ea 80 ?? ?? ?? e0 03 14 aa 2b 04 00 94 f4 03 00 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AE_2147917786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AE!MTB"
        threat_id = "2147917786"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 1c 21 6e 20 83 86 3c e0 bf 47 fd 48 e6 01 0f 00 1c 28 2e e0 bf 07 fd 09 1f 00 12 56 06 80 52 29 01 16 4a e9 03 3e 39 e8 4b 02 f9 48 0a 80 52 e8 0b 09 79 48 a6 88 52 c8 aa a8 72}  //weight: 1, accuracy: High
        $x_1_2 = {09 6a 82 52 b5 02 09 8b e8 03 02 f9 e1 23 10 91 e2 03 10 91 e0 03 15 aa c1 3e 00 94 e8 83 36 91 08 01 40 b2 c9 0a 80 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AJ_2147919057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AJ!MTB"
        threat_id = "2147919057"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 41 00 51 eb 43 00 91 4b 0d 40 b3 0a 69 69 38 6b 01 40 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 49 02 f1}  //weight: 1, accuracy: High
        $x_1_2 = {bf 6a 34 38 e8 1f 46 39 09 1d 00 13 ea 2f 57 a9 3f 01 00 71 e9 c3 05 91 41 b1 89 9a 62 b1 88 9a e0 43 1f 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AN_2147919058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AN!MTB"
        threat_id = "2147919058"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 04 80 52 08 00 08 4a e8 83 02 39 2a fc 78 d3 48 09 1c 52 e8 7f 02 39 2b fc 70 d3 e9 0d 80 52 68 01 09 4a e8 7b 02 39 2c fc 68 d3 93 0e 80 52 88 01 13 4a e8 77 02 39 2d fc 60 d3 68 0e 80 52 ae 01 08 4a 68 0e 80 52 ee 73 02 39 2e fc 58 d3 cf 01 1b 52 ef 6f 02 39}  //weight: 1, accuracy: High
        $x_1_2 = {1f 21 00 f1 00 ?? ?? ?? 2a 01 08 8b 4b 01 40 39 4c 41 40 39 8b 01 0b 4a 4b 41 00 39 08 05 00 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AO_2147919063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AO!MTB"
        threat_id = "2147919063"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "walletwasabi/client/Wallets/" ascii //weight: 5
        $x_5_2 = "Exodus/exodus.wallet/" ascii //weight: 5
        $x_1_3 = "atomic/Local Stveldb/" ascii //weight: 1
        $x_1_4 = "Guarda/Local Storage/leveldb/" ascii //weight: 1
        $x_1_5 = {ff 43 01 d1 fd 7b 04 a9 fd 03 01 91 a0 83 1f f8 a8 83 5f f8 e8 07 00 f9 e0 83 00 91 e0 03 00 f9 61 00 00 f0 21 f8 06 91 6a ?? ?? ?? e1 03 40 f9 e2 07 40 f9 e0 03 02 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Amos_T_2147919521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.T!MTB"
        threat_id = "2147919521"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f6 c7 01 48 8d 85 31 ef ff ff 48 0f 44 d8 4d 85 e4 74 ?? 48 8d 75 b1 41 f6 c5 01 74 ?? 48 8b 75 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 3d 02 01 00 4d 8d 3c 04 49 83 ff f0 0f 83 4d 0d 00 00 49 89 c6 49 83 ff 16 77 ?? 0f 57 c0 0f 29 85 30 ef ff ff 48 c7 85 40 ef ff ff 00 00 00 00 45 00 ff 44 88 bd 30 ef ff ff 31 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AQ_2147919678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AQ!MTB"
        threat_id = "2147919678"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 e0 02 89 ca c0 ea 04 80 e2 03 08 c2 88 55 d1 c0 e1 04 8a 45 d6 c0 e8 02 24 0f 08 c8 88 45 d2 8b 45 c8 83 f8 02 6a 01 41 5e 44 0f 4d f0 41 ff ce 45 31 ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f 95 c0 0f b6 c0 5d c3 90 48 85 f6 74 13 55 48 89 e5 48 89 f0 0f be 32 48 89 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AC_2147920058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AC!MTB"
        threat_id = "2147920058"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 89 b4 94 60 01 00 00 41 0f b6 94 0c 4b 8f 00 00 8b b4 94 60 01 00 00 ff c6 ?? ?? 89 b4 94 60 01 00 00 41 0f b6 94 0c 4c 8f 00 00 8b b4 94 60 01 00 00 ff c6 ?? ?? 89 b4 94 60 01 00 00 48 81 f9 1d 01 00 00 ?? ?? 41 0f b6 94 0c 4d 8f 00 00 8b b4 94 60 01 00 00 48 83 c1 03 ff c6 ?? ?? 67 0f b9}  //weight: 1, accuracy: Low
        $x_1_2 = {74 36 49 8b 45 f0 48 39 d8 ?? ?? 48 8d 68 e8 f6 40 e8 01 ?? ?? 48 8b 78 f8 e8 ed 03 00 00 48 89 e8 48 39 dd ?? ?? 49 8b 3c 24 ?? ?? 48 89 df 49 89 5d f0 e8 d3 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AH_2147920060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AH!MTB"
        threat_id = "2147920060"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 01 0b 6b a1 00 00 54 8a 00 00 b0 4a f1 43 79 2a 69 02 b9 1f 00 00 14 e9 2f 40 f9 6a 67 81 52 49 01 09 4b ea 2f 40 f9 eb 3f c1 39 29 7d 0a 1b ea 72 8a 52 2a 68 bd 72 29 29 0b 1b 8a 00 00 b0}  //weight: 1, accuracy: High
        $x_1_2 = {ad 3d 10 53 bf c1 57 71 2d 02 00 54 2a 6d 1c 53 4a 01 09 4b 8a 29 08 39 ea 4b 40 b9 ec 4b 40 b9 4a 31 0e 1b ea 4b 00 b9 10 00 00 14 8a 00 00 b0 4a 99 44 79 aa 01 00 34 ea 43 40 b9 0a 01 00 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AR_2147920163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AR!MTB"
        threat_id = "2147920163"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 56 40 49 8b be 80 00 00 00 49 8b 4e 60 48 01 d1 48 8b 07 4c 89 e6 ?? ?? ?? ?? ?? ?? ?? ff 50 28 89 c3 4c 8b ad 50 ff ff ff 49 8b 7e 40 49 8b 4e 78 49 29 fd 4c 89 fe 4c 89 ea e8 b4 2b 00 00 4c 39 e8 75 ?? 83 fb 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 09 c8 f3 0f 5e c1 66 0f 3a 0a c0 0a f3 48 0f 2c c8 48 89 ca 48 c1 fa 3f f3 0f 5c 05 8b 3c 00 00 f3 48 0f 2c f0 48 21 d6 48 09 ce 48 39 f0 48 0f 47 f0 4c 89 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AU_2147920165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AU!MTB"
        threat_id = "2147920165"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e8 48 8b 45 f0 88 45 e7 e8 fc ?? ?? ?? 8a 55 e7 48 8b 7d e8 8a 08 80 e2 7f c0 e2 01 80 e1 01 08 d1 88 08 e8 e1 ?? ?? ?? 8a 08 80 e1 fe 80 c9 00 88 08 48 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 f0 48 3b 45 e8 0f 84 ?? ?? ?? ?? 48 8b 7d c0 48 8b 75 f0 e8 e5 ?? ?? ?? 48 8b 45 f0 48 83 c0 01 48 89 45 f0 48 8b 45 c0 48 83 c0 01 48 89 45 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AV_2147921840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AV!MTB"
        threat_id = "2147921840"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0b f6 c1 01 75 36 48 89 c8 48 d1 e8 41 bf 16 00 00 00 48 8b 5d c0 3c 16 74 5e 80 e1 fe 80 c1 02}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 95 d8 fe ff ff 30 11 0f b6 95 d8 fe ff ff 30 51 01 30 51 02 0f b6 95 d8 fe ff ff 30 51 03 30 51 04 48 83 c1 05 48 39 c1 75 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AS_2147923435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AS!MTB"
        threat_id = "2147923435"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 95 58 ff ff ff 30 11 0f b6 95 58 ff ff ff 30 51 01 30 51 02 0f b6 95 58 ff ff ff 30 51 03 30 51 04 48 83 c1 05 48 39 c1}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 4b f8 49 89 4f f8 0f 10 4b e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 43 e8 48 c7 43 f8 00 00 00 00 48 8d 4b e8 48 89 cb 4c 39 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AT_2147923436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AT!MTB"
        threat_id = "2147923436"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 08 aa 08 48 82 52 e8 1b 00 79 48 e2 88 52 28 e8 aa 72 e8 0b 00 b9 e8 23 00 91 00 01 40 b2 29 00 80 52}  //weight: 1, accuracy: High
        $x_1_2 = {08 a4 40 a9 1f 01 09 eb 22 ?? ?? ?? 20 00 c0 3d 29 08 40 f9 09 09 00 f9 00 85 81 3c 3f fc 00 a9 3f 00 00 f9 08 04 00 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AW_2147923439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AW!MTB"
        threat_id = "2147923439"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 07 40 f9 e9 03 00 aa e0 03 40 f9 e9 0f 00 f9 e9 03 01 aa e9 17 00 b9 01 21 00 91 e8 0f 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {ff c3 00 d1 fd 7b 02 a9 fd 83 00 91 88 00 00 d0 08 c1 0a 91 09 41 00 91 a0 83 1f f8 a8 83 5f f8 e8 03 00 f9 09 01 00 f9 00 01 01 91 a0 0f 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AX_2147923440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AX!MTB"
        threat_id = "2147923440"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 89 7d f8 48 8b 45 f8 48 8b 0d a5 a4 00 00 48 83 c1 10 48 89 08 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 20 48 89 7d f0 48 89 75 e8 48 8b 7d f0 48 8b 45 e8 48 89 45 e0 e8 ?? ?? ?? ?? 48 89 c1 48 8b 45 e0 48 39 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AA_2147923515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AA!MTB"
        threat_id = "2147923515"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 95 0a e7 ff ff 48 89 d6 41 80 f6 68 44 88 b5 09 e7 ff ff 88 9d 08 e7 ff ff 41 0f b6 d6 66 0f 3a 20 c2 07 48 8b 95 20 c6 ff ff 88 95 07 e7 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {40 0f b6 d6 66 0f 3a 20 c2 08 48 8b 95 50 c6 ff ff 88 95 06 e7 ff ff 40 0f b6 d7 66 0f 3a 20 c2 09 48 8b 95 48 c6 ff ff 88 95 05 e7 ff ff 41 0f b6 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AL_2147923516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AL!MTB"
        threat_id = "2147923516"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa e3 ff ff 97 e0 03 13 aa b9 05 00 94 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6}  //weight: 1, accuracy: High
        $x_1_2 = {e0 03 13 aa c8 00 00 94 f4 03 00 aa e0 03 13 aa 06 01 00 94 9f 02 00 eb 82 ?? ?? ?? 80 02 c0 39 04 01 00 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AF_2147923517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AF!MTB"
        threat_id = "2147923517"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ec 7f c1 39 ed 27 40 f9 6e 02 08 8b ce 05 40 39 2f 21 47 39 ce 01 0f 4a 9f 01 00 71 ac b1 8a 9a 8c 01 08 8b 8e 05 00 39 08 05 00 91 1f 01 0b eb 81 ?? ?? ?? 88 01 80 52 e8 1f 01 39 e8 e5 8d 52 88 0d af 72 e8 3b 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 73 40 f9 56 02 00 b4 e8 37 40 f9 08 19 40 f9 e0 03 14 aa 00 01 3f d6 f5 03 00 aa e0 03 16 aa 10 07 00 94 f6 03 00 aa ff 73 00 f9 e8 37 40 f9 08 0d 40 f9 e0 03 14 aa 01 00 80 d2 02 00 80 d2 00 01 3f d6 c8 02 15 2a 08 ?? ?? ?? e8 33 40 f9 08 81 5e f8 e9 83 01 91 20 01 08 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AI_2147923831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AI!MTB"
        threat_id = "2147923831"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 13 eb 00 48 89 c3 48 8d bd 78 ff ff ff e8 f7 1e 00 00 eb 03 48 89 c3 48 8d bd 60 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {75 28 31 c0 48 81 c4 f8 00 00 00 5b 41 5c 41 5d 41 5e 41 5f 5d c3 8b 85 6c ff ff ff 04 07 88 45 9e 31 ff e8 87 17 00 00 0f 0b e8 7a 17 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AM_2147923832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AM!MTB"
        threat_id = "2147923832"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 f9 41 ff c7 88 44 0d d5 41 83 ff 03 75 69 8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 89 c2 c0 ea 06 c0 e1 02 08 d1 80 e1 3f}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 c6 44 0d d5 00 ff c0 83 f8 03 75 f2 8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 c0 e8 06 c0 e1 02 08 c1 80 e1 3f 88 4d d3 45 85 ff 78 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AP_2147923833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AP!MTB"
        threat_id = "2147923833"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 09 48 8b 7d e0 e8 ea 04 00 00 48 89 df e8 e2 04 00 00 31 c0 48 83 c4 38 5b 41 5e 41 5f 5d c3 48 8d 35 ac 07 00 00 e8 9d 00 00 00 48 89 c7 e8 c5 00 00 00 bf 01 00 00 00 e8 db 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 7d c0 4d 01 fe 41 81 e5 b0 00 00 00 41 83 fd 20 4c 89 fa 49 0f 44 d6 44 0f be c8 4c 89 fe 4c 89 f1 4d 89 e0 e8 9e 00 00 00 48 85 c0 75 17 48 8b 03 48 8b 40 e8 48 8d 3c 03 8b 74 03 20 83 ce 05 e8 82 02 00 00 48 8d 7d b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AZ_2147923964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AZ!MTB"
        threat_id = "2147923964"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 3f c1 39 68 00 f8 36 e0 1f 40 f9 41 00 00 94 e0 03 14 aa 3f 00 00 94 e0 03 13 aa 3d 00 00 94 e0 03 15 aa 2c 00 00 94 e0 07 40 f9 39 00 00 94 e8 df c0 39 68 fe ff 36}  //weight: 1, accuracy: High
        $x_1_2 = {4a 05 00 11 4a 1d 40 92 6b 6a 6a 38 69 01 09 0b 2c 1d 40 92 6d 6a 6c 38 6d 6a 2a 38 6b 6a 2c 38 6c 6a 6a 38 8b 01 0b 0b 6b 1d 40 92 6b 6a 6b 38 ec 07 40 f9 8b 69 28 38 08 05 00 91 ff 02 08 eb 01 fe ff 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AK_2147924459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AK!MTB"
        threat_id = "2147924459"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 89 fb e8 81 f1 ff ff 48 89 df e8 07 16 00 00 5b 41 5e 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d7 00 48 8d 75 d7 48 89 df e8 a8 fc ff ff 48 83 c4 18 5b 41 5c 41 5d 41 5e 41 5f 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AY_2147924462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AY!MTB"
        threat_id = "2147924462"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 b8 88 0c 08 48 89 c8 31 d2 49 f7 f5 49 8b 04 24 8a 04 10 48 8b 55 88 88 04 0a 48 ff c1 48 81 f9 00 01 00 00 75 ?? 31 c0 31 c9 4c 8b bd 78 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 57 c0 4c 8b 75 c8 41 0f 11 06 49 c7 46 10 00 00 00 00 45 31 ff 4c 8d 2d ff 8c 00 00 31 db 45 31 e4 31 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BB_2147924810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BB!MTB"
        threat_id = "2147924810"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 01 c7 46 88 2c 30 4c 39 e3 0f ?? ?? ?? ?? ?? 49 83 fe 08 0f ?? ?? ?? ?? ?? 48 89 ca 48 89 de 89 f7 44 29 e7 4c 89 e1 48 f7 d1 48 01 f1 48 83 e7 07}  //weight: 1, accuracy: Low
        $x_1_2 = {44 89 e9 c1 e1 05 48 89 c6 48 09 ce 41 83 fe 03 0f ?? ?? ?? ?? ?? 44 89 f1 83 c1 fd 41 89 f5 89 4d d4 41 d3 ed 49 8b 44 24 10 48 39 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BC_2147924811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BC!MTB"
        threat_id = "2147924811"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 7e 10 48 8b 75 a8 40 8a 34 16 40 32 34 17 f6 03 01 48 89 cf 74 ?? 48 8b 7b 10 40 88 34 17 48 ff c2}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 41 56 53 48 83 ec 10 0f 57 c0 48 83 67 10 00 0f 11 07 48 89 7d e0 c6 45 e8 00 48 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CA_2147925277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CA!MTB"
        threat_id = "2147925277"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 01 12 00 00 0f be f0 48 89 df e8 b7 12 00 00 48 89 df e8 b5 12 00 00 48 89 d8 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 8b 06 48 89 07 48 8b 4e 40 48 8b 40 e8 48 89 0c 07 48 8b 46 48 48 89 47 10 48 83 c7 18 e8 7a 00 00 00 48 83 c3 08 4c 89 f7 48 89 de 5b 41 5e 5d e9 b0 11 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CB_2147925279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CB!MTB"
        threat_id = "2147925279"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d bd 60 ff ff ff e8 5f 14 00 00 48 8d bd 48 ff ff ff e8 53 14 00 00 48 8d 7d a8 e8 4a 14 00 00 31 c0 48 81 c4 b0 00 00 00 5b 41 5e 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 6d 13 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 03 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BQ_2147925438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BQ!MTB"
        threat_id = "2147925438"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c9 5e c0 39 ca 02 40 f9 3f 01 00 71 49 b1 96 9a 29 69 68 38 ea 07 40 f9 4a 69 68 38 49 01 09 4a aa 5e c0 39 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 49 69 28 38 08 05 00 91 ff 02 08 eb}  //weight: 1, accuracy: High
        $x_1_2 = {4a 05 00 11 4a 1d 40 92 6b 6a 6a 38 69 01 09 0b 2c 1d 40 92 6d 6a 6c 38 6d 6a 2a 38 6b 6a 2c 38 6c 6a 6a 38 8b 01 0b 0b 6b 1d 40 92 6b 6a 6b 38 ec 07 40 f9 8b 69 28 38 08 05 00 91 ff 02 08 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CC_2147925625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CC!MTB"
        threat_id = "2147925625"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 c0 40 8a 34 0a 40 00 f0 48 8b 7d 90 02 04 0f 0f b6 f8 44 8a 04 3a 44 88 04 0a 40 88 34 3a 48 ff c1}  //weight: 1, accuracy: High
        $x_1_2 = {49 39 cf 74 ?? 49 8b 36 48 8b 55 a8 8a 14 0a 32 14 0e f6 03 01 48 89 c6 74 ?? 48 8b 73 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BR_2147926125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BR!MTB"
        threat_id = "2147926125"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 09 c8 f3 0f 5e c1 66 0f 3a 0a c0 0a f3 48 0f 2c c8 48 89 ca 48 c1 fa 3f f3 0f 5c 05 8b 0d 00 00 f3 48 0f 2c f8 48 21 d7 48 09 cf 48 39 f8 48 0f 47 f8 41 bd 02 00 00 00 48 83 ff 01 74 ?? 48 8d 47 ff 48 85 c7 75 18}  //weight: 1, accuracy: Low
        $x_1_2 = {41 be 08 00 00 00 49 29 d6 85 d2 74 ?? 83 fa 08 74 ?? b9 40 00 00 00 48 29 d1 4c 39 f1 4c 89 f6 48 0f 42 f1 29 f1 48 c7 c7 ff ff ff ff 48 d3 ef 89 d1 48 d3 ef 48 d3 e7 48 f7 d7 48 21 f8 48 89 03 49 29 f6 48 83 c3 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BT_2147926541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BT!MTB"
        threat_id = "2147926541"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 ?? ?? ?? ?? 0f be f0 48 89 df e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 48 89 d8 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d bd 60 ff ff ff e8 ?? ?? ?? ?? 48 8d bd 48 ff ff ff e8 ?? ?? ?? ?? 48 8d 7d a8 e8 ?? ?? ?? ?? 31 c0 48 81 c4 b0 00 00 00 5b 41 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BU_2147926542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BU!MTB"
        threat_id = "2147926542"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b 4d 2c 41 8d 04 19 83 f8 01 0f 86 ce 00 00 00 41 8b 45 24 8d 54 18 fe 48 89 d1 bf ff 7f 00 00 48 21 f9 41 0f b6 b4 0d c8 00 00 00 8d 4c 18 ff 48 21 f9 45 0f b6 94 0d c8 00 00 00 b9 02 01 00 00 29 d9 49 39 cf 49 0f 42 cf 4d 89 f8}  //weight: 1, accuracy: High
        $x_1_2 = {4d 89 bd b8 00 00 00 31 c0 49 89 85 c0 00 00 00 45 89 8d a8 00 00 00 49 39 45 00 0f 94 c0 48 89 ce 4c 09 c6 0f 95 c3 30 c3 75 ?? 41 83 bd 84 00 00 00 00 75 ?? 41 8b 85 80 00 00 00 41 83 f9 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BV_2147926543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BV!MTB"
        threat_id = "2147926543"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 7d e0 48 89 47 08 48 89 07 48 8b 07 48 8b 4d f0 48 c1 e1 02 48 01 c8 48 89 45 d8 e8 ?? ?? ?? ?? 48 8b 4d d8 48 8b 7d e0 48 89 08 31 c0 89 c6 e8 ?? ?? ?? ?? 48 83 c4 30 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 83 ec 20 89 7d fc 48 89 75 f0 8b 7d fc e8 ?? ?? ?? ?? 83 f8 00 0f ?? ?? ?? ?? ?? 48 63 4d fc 48 8b 05 ad 9f 00 00 8b 44 88 3c 48 23 45 f0 48 83 f8 00 0f 95 c0 34 ff 34 ff 88 45 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BX_2147926544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BX!MTB"
        threat_id = "2147926544"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 31 c0 48 81 c4 a8 00 00 00 5b 41 5c 41 5d 41 5e 41 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 3c 10 41 89 14 b9 0f b6 7c 10 01 44 8d 42 01 45 89 04 b9 0f b6 7c 10 02 44 8d 42 02 45 89 04 b9 0f b6 7c 10 03 44 8d 42 03 45 89 04 b9 48 83 c2 04 48 39 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CD_2147926713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CD!MTB"
        threat_id = "2147926713"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa 08 00 40 f9 08 81 5e f8 00 00 08 8b 41 01 80 52 96 04 00 94 e1 03 00 aa e0 03 13 aa e6 04 00 94 e0 03 13 aa e7 04 00 94 e0 03 13 aa fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6}  //weight: 1, accuracy: High
        $x_1_2 = {fd 7b bf a9 fd 03 00 91 00 01 80 52 03 05 00 94 ba 04 00 94 61 00 00 d0 21 1c 40 f9 62 00 00 d0 42 08 40 f9 09 05 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CE_2147926714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CE!MTB"
        threat_id = "2147926714"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 cb 05 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 91 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 8f 04 00 00 0f be f0 48 89 df e8 39 05 00 00 48 89 df e8 37 05 00 00 48 89 d8 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BW_2147927442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BW!MTB"
        threat_id = "2147927442"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 3f c1 39 88 01 f8 37 e8 9f c1 39 08 02 f8 36 0d 00 00 14 e0 07 40 f9 ba 01 00 94 e8 df c0 39 08 ff ff 36}  //weight: 1, accuracy: High
        $x_1_2 = {1c 1a 80 52 68 c3 00 51 1f 29 00 71 63 02 00 54 1d 00 00 14 c8 06 40 f9 3f 03 08 eb 42 0b 00 54 c8 02 40 f9 08 01 19 8b 1a 01 40 39 1b 05 40 39 48 c3 00 51 1f 29 00 71 43 fe ff 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BY_2147927667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BY!MTB"
        threat_id = "2147927667"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 03 16 aa 7f 01 00 94 f6 03 00 aa 60 00 00 b0 00 08 40 f9 61 00 00 90 21 54 3c 91 e2 00 80 52 8a 00 00 94 f7 03 00 aa c8 02 40 f9 08 09 40 f9 e0 03 16 aa 00 01 3f d6 f6 03 00 aa 86 01 00 94 e2 03 00 aa e0 03 17 aa e1 03 16 aa 7f 00 00 94 38 00 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {08 16 80 52 28 03 08 0a 83 02 15 8b 1f 81 00 71 62 00 94 9a 05 1f 00 13 e0 03 17 aa e1 03 14 aa e4 03 16 aa 2a 00 00 94 00 01 00 b5 68 02 40 f9 08 81 5e f8 60 02 08 8b 08 20 40 b9 a9 00 80 52 01 01 09 2a a8 00 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BZ_2147927669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BZ!MTB"
        threat_id = "2147927669"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c8 02 40 f9 e0 03 16 aa 00 01 3f d6 e1 03 00 aa 38 00 80 52 18 e8 00 39 48 00 00 f0 08 b1 06 91 00 05 40 ad 00 04 00 ad 00 09 c0 3d 00 08 80 3d 00 a1 c2 3c 00 a0 82 3c 00 00 00 b0 00 d0 02 91 e2 ff ff b0 42 00 00 91 e9 28 00 94 e0 03 15 aa e0 02 3f d6 18 00 00 39}  //weight: 1, accuracy: High
        $x_1_2 = {a8 02 40 f9 e0 03 15 aa 00 01 3f d6 e1 03 00 aa 37 00 80 52 17 08 00 39 28 f7 88 52 08 00 00 79 00 00 00 b0 00 f0 01 91 e2 ff ff b0 42 00 00 91 8d 2a 00 94 e0 03 14 aa c0 02 3f d6 17 00 00 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CF_2147927670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CF!MTB"
        threat_id = "2147927670"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c3 03 d1 f8 5f 0b a9 f6 57 0c a9 f4 4f 0d a9 fd 7b 0e a9 fd 83 03 91 b5 83 01 d1 00 0a 80 52 0b 02 00 94 f3 03 00 aa a0 83 1b f8 08 00 00 b0 00 ad c2 3d a0 02 82 3c 08 00 00 b0 08 99 2b 91 00 05 40 ad 00 04 00 ad 00 05 41 ad 00 04 01 ad 1f 00 01 39}  //weight: 1, accuracy: High
        $x_1_2 = {1f f0 00 39 e8 43 01 91 a0 83 01 d1 c9 fe ff 97 e8 e3 00 91 e0 43 01 91 a1 23 01 d1 08 fe ff 97 e8 83 00 91 e0 a3 01 91 c2 fe ff 97 f6 23 00 91 e8 23 00 91 e0 83 00 91 a1 23 01 d1 00 fe ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CG_2147927671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CG!MTB"
        threat_id = "2147927671"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e0 23 00 91 76 2a 00 94 e0 23 00 91 53 ff ff 97 1f 00 00 f1 e0 13 9f 5a a8 83 5c f8 69 00 00 b0 29 3d 40 f9 29 01 40 f9 3f 01 08 eb 41 ?? ?? ?? ff 43 08 91 fd 7b 43 a9 f4 4f 42 a9 f6 57 41 a9 f8 5f c4 a8}  //weight: 1, accuracy: Low
        $x_1_2 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f3 03 02 aa f5 03 01 aa f4 03 00 aa 97 00 00 b0 f7 42 0f 91 f8 02 40 f9 e0 03 17 aa 00 03 3f d6 08 00 40 39 96 00 00 b0 d6 e2 0e 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CL_2147929101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CL!MTB"
        threat_id = "2147929101"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 89 f0 48 c1 e8 3e 75 1a 48 89 f3 48 8d 3c b5 00 00 00 00 e8 89 01 00 00 48 89 da 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 54 53 49 89 f7 48 89 fb 48 89 f7 e8 df 00 00 00 48 83 f8 f0 73 58 49 89 c6 48 83 f8 17 73 10 43 8d 04 36 88 03 48 ff c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CJ_2147929345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CJ!MTB"
        threat_id = "2147929345"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 83 00 91 a1 e3 00 d1 15 ff ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71 20 b1 96 9a 77 00 00 94 e8 3f c1 39 e9 1f 40 f9 1f 01 00 71 e8 e3 00 91 20 b1 88 9a 71 00 00 94 e8 7f c0 39 68 02 f8 37 e8 df c0 39}  //weight: 1, accuracy: High
        $x_1_2 = {f6 03 00 aa e8 9f c1 39 28 02 f8 37 12 00 00 14 f6 03 00 aa 10 00 00 14 f6 03 00 aa 10 00 00 14 f6 03 00 aa 10 00 00 14 f6 03 00 aa e8 7f c0 39 28 02 f8 37 e8 df c0 39 68 02 f8 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CQ_2147929613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CQ!MTB"
        threat_id = "2147929613"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 31 c0 48 81 c4 c0 00 00 00 5b 41 5c 41 5e 41 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb e8 ?? ?? ?? ?? 48 8b 05 63 c7 00 00 48 83 c0 10 48 89 03 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CN_2147930745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CN!MTB"
        threat_id = "2147930745"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 53 01 00 00 f6 45 c8 01 75 45 f6 45 98 01 75 4e f6 45 b0 01 75 57 f6 45 80 01 74 09 48 8b 7d 90 e8 14 01 00 00 4c 89 ff e8 0c 01 00 00 4c 89 f7 e8 04 01 00 00 48 89 df e8 fc 00 00 00 31 c0 48 81 c4 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 89 c4 f6 45 98 01 74 36 eb 78 49 89 c4 f6 45 b0 01 74 31 eb 7c 49 89 c4 f6 45 80 01 75 2c eb 33 49 89 c4 eb 2e 49 89 c4 eb 31 49 89 c4 eb 34 49 89 c4 f6 45 c8 01 75 3b f6 45 98 01 75 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CR_2147930746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CR!MTB"
        threat_id = "2147930746"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 74 65 72 5f 74 6f 42 38 6e 65 31 38 30 31 30 30 45 52 53 31 5f 00 5f 5f 5a 4e 4b 53 74 33 5f 5f 31 34 66 70 6f 73 49 31 31 5f 5f 6d 62 73 74 61 74 65 5f 74 45 63 76 78 42 38 6e 65 31 38 30 31 30 30 45 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 40 5f 5f 5a 4e 53 74 33 5f 5f 31 31 35 62 61 73 69 63 5f 73 74 72 69 6e 67 62 75 66 49 63 4e 53 5f 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 45 4e 53 5f 39 61 6c 6c 6f 63 61 74}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 7d e0 e8 8b 17 00 00 48 83 c4 20 5d c3 48 8b 7d e0 48 89 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MacOS_Amos_CH_2147930749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CH!MTB"
        threat_id = "2147930749"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 03 15 aa ad 00 00 94 e0 03 14 aa ab 00 00 94 e0 03 13 aa a9 00 00 94 00 00 80 52 fd 7b 4e a9 f4 4f 4d a9 f6 57 4c a9 ff c3 03 91 c0 03 5f d6}  //weight: 1, accuracy: High
        $x_1_2 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f4 03 00 aa 00 02 80 52 35 00 00 94 f3 03 00 aa e1 03 14 aa 0c 00 00 94 61 00 00 b0 21 0c 40 f9 62 00 00 b0 42 00 40 f9 e0 03 13 aa 3b 00 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CI_2147930750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CI!MTB"
        threat_id = "2147930750"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 49 89 fe bf 10 00 00 00 e8 ?? ?? ?? ?? 48 89 c3 48 89 c7 4c 89 f6 e8 ?? ?? ?? ?? 48 8b 35 df c7 00 00 48 8b 15 c0 c7 00 00 48 89 df}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 31 c0 48 81 c4 c0 00 00 00 5b 41 5c 41 5e 41 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CM_2147930752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CM!MTB"
        threat_id = "2147930752"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f5 03 01 aa f3 03 00 aa e0 03 01 aa 55 00 00 94 e8 eb 7c b2 1f 00 08 eb 62 ?? ?? ?? f4 03 00 aa 1f 5c 00 f1 a2 ?? ?? ?? 74 5e 00 39 f6 03 13 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f4 03 00 aa 00 02 80 52 73 00 00 94 f3 03 00 aa e1 03 14 aa 0c 00 00 94 61 00 00 b0 21 08 40 f9 62 00 00 b0 42 00 40 f9 e0 03 13 aa 70 00 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CP_2147930755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CP!MTB"
        threat_id = "2147930755"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c3 01 d1 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f6 03 01 aa f5 03 00 aa f4 03 08 aa 00 80 80 52 f9 01 00 94 f3 03 00 aa e1 1f 80 52 02 80 80 52 10 02 00 94 c8 5e c0 39 68 ?? ?? ?? 08 1d 40 92 e0 03 13 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {9f 7e 00 a9 9f 0a 00 f9 a8 5e 40 39 09 1d 00 13 aa 2e 40 a9 3f 01 00 71 59 b1 95 9a 69 b1 88 9a 49 ?? ?? ?? 1a 00 80 52 08 00 80 52 2a 03 09 8b ea 07 00 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CO_2147930907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CO!MTB"
        threat_id = "2147930907"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c3 03 d1 fc 6f 09 a9 fa 67 0a a9 f8 5f 0b a9 f6 57 0c a9 f4 4f 0d a9 fd 7b 0e a9 fd 83 03 91 f6 03 02 aa f3 03 01 aa f4 03 00 aa 83 01 00 34 e0 03 14 aa e1 03 13 aa e2 03 16 aa fd 7b 4e a9 f4 4f 4d a9 f6 57 4c a9 f8 5f 4b a9 fa 67 4a a9 fc 6f 49 a9 ff c3 03 91}  //weight: 1, accuracy: High
        $x_1_2 = {ff c3 01 d1 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f3 03 08 aa 1f 7d 00 a9 1f 09 00 f9 08 5c 40 39 09 1d 00 13 0a 2c 40 a9 3f 01 00 71 59 b1 80 9a 7a b1 88 9a fa 2e 00 b4 15 00 80 52 fc 37 00 91 58 01 00 f0 18 e3 09 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CS_2147931342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CS!MTB"
        threat_id = "2147931342"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c3 4c 89 ff 4c 89 f6 48 89 da 5b 41 5c 41 5e 41 5f 5d e9 82 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 89 f8 48 8b 3f 48 85 ff 74 09 48 89 78 08 e8 32 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CT_2147931449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CT!MTB"
        threat_id = "2147931449"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 48 81 ec c8 00 00 00 48 8d 35 5c 07 00 00 48 8d 7d 98 e8 1c 04 00 00 48 8d 35 8d 07 00 00 48 8d bd 38 ff ff ff e8 09 04 00 00 48 8d 35 2f cb 00 00 48 8d bd 50 ff ff ff e8 f6 03 00 00 48 8d bd 68 ff ff ff 48 8d b5 38 ff ff ff e8 86 fe ff ff 48 8d 7d b0 48 8d b5 68 ff ff ff 48 8d 55 98 e8 37 fd ff ff 48 8d 7d 80 48 8d b5 50 ff ff ff e8 62 fe ff ff 48 8d 7d c8 48 8d 75 80 48 8d 55 98 e8 16 fd ff ff f6 45 c8 01 74 06 48 8b 7d d8 eb 04}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 f0 48 83 e0 f8 48 83 c0 08 4d 89 f4 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 1b 01 00 00 48 89 43 10 49 83 cc 01 4c 89 23 4c 89 73 08 48 89 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CV_2147931812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CV!MTB"
        threat_id = "2147931812"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 fb f8 73 50 48 89 d8 48 83 e0 f8 48 83 c0 08 49 89 dc 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 5e 00 00 00 49 89 47 10 49 83 cc 01 4d 89 27 49 89 5f 08 49 89 c7 48 ff c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 28 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 1c 40 f6 c6 02 0f 85 fb 00 00 00 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 d1 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CU_2147933239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CU!MTB"
        threat_id = "2147933239"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7f 7e 00 a9 7f 0a 00 f9 01 fd 41 d3 e0 03 13 aa 8b 01 00 94 16 00 80 d2 17 00 80 d2 58 00 80 52 f9 23 00 91 03 00 00 14}  //weight: 1, accuracy: High
        $x_1_2 = {ff c3 01 d1 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f4 03 00 aa f3 03 08 aa 08 5c c0 39 a8 00 f8 37 09 1d 00 12 e9 06 00 37 08 1d 40 92 03 00 00 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CW_2147933240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CW!MTB"
        threat_id = "2147933240"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 28 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 1c 40 f6 c6 02 0f 85 fb 00 00 00 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 d1 ee eb 1c}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 34 14 89 14 b3 41 0f b6 74 14 01 8d 7a 01 89 3c b3 41 0f b6 74 14 02 8d 7a 02 89 3c b3 41 0f b6 74 14 03 8d 7a 03 89 3c b3 48 83 c2 04 48 39 ca 75 cb 48 85 c0 74 16 66 0f 1f 44 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CK_2147933282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CK!MTB"
        threat_id = "2147933282"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 17 00 f9 e1 e3 00 91 21 78 60 f8 e1 1b 00 f9 e4 e3 00 94 5f e4 00 94 e0 1b 40 f9 e5 e5 00 94 00 e4 00 94 e0 17 40 f9 00 04 00 91 1f 40 00 f1 8b fe ff 54}  //weight: 1, accuracy: High
        $x_1_2 = {90 0b 40 f9 ff 63 30 eb 49 03 00 54 fe 0f 1e f8 fd 83 1f f8 fd 23 00 d1 5f 20 00 f1 e8 01 00 54 c2 01 00 b4 43 04 00 d1 5f 00 03 ea 61 01 00 54 3f 40 00 f1 c2 00 00 54 1b 00 80 39 00 0c 01 8b fd fb 7f a9 ff 83 00 91 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CZ_2147934758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CZ!MTB"
        threat_id = "2147934758"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 a5 02 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 f7 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 7d f0 e8 2b 01 00 00 48 8b 4d f0 48 8b 31 48 83 21 00 48 89 c7 e8 2e 00 00 00 48 8b 45 f0 ff 50 08 48 8d 7d f0 e8 2c 00 00 00 31 c0 48 83 c4 08 5b 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DC_2147935138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DC!MTB"
        threat_id = "2147935138"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 37 40 f6 c6 01 74 06 49 8b 7f 08 eb 04 89 f7 d1 ef 48 39 f9 73 19 48 89 c7 40 f6 c6 01 74 04 49 8b 7f 10 0f b6 34 0f 89 0c b2 48 ff c1 eb ce}  //weight: 1, accuracy: High
        $x_1_2 = {4d 39 f4 74 3f 41 0f b6 04 24 48 8b 4d b8 8b 04 81 85 c0 78 2a 41 c1 e5 06 41 09 c5 41 83 c7 06 41 83 ff 08 7c 19 41 83 c7 f8 44 89 e8 44 89 f9 d3 f8 0f be f0 48 89 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DD_2147935644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DD!MTB"
        threat_id = "2147935644"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ab 5e 40 39 6a 1d 00 13 ac 06 40 f9 5f 01 00 71 8b b1 8b 9a 1f 01 0b eb 02 01 00 54 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 4a 69 68 38 28 79 2a b8 08 05 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {08 00 80 52 15 00 80 52 7f 7e 00 a9 7f 0a 00 f9 89 5e 40 39 2a 1d 00 13 8b 32 40 a9 5f 01 00 71 74 b1 94 9a 89 b1 89 9a 96 02 09 8b 9f 02 16 eb 20 02 00 54 89 02 40 39 ea 07 40 f9 49 79 69 b8 69 01 f8 37 35 19 15 2a 08 19 00 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DA_2147935666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DA!MTB"
        threat_id = "2147935666"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 8c 24 98 00 00 00 48 8b 44 cc 20 48 89 44 24 18 e8 f4 44 03 00 e8 ef 46 03 00 48 8b 44 24 18 e8 c5 47 03 00 0f 1f 44 00 00 e8 3b 45 03 00 48 8b 8c 24 98 00 00 00 48 ff c1 48 8b 84 24 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 44 24 68 48 89 4c 24 28 66 90 e8 db 07 03 00 48 8d 05 0b a8 8b 00 bb 21 00 00 00 e8 2a 0d 03 00 48 8b 44 24 68 48 8b 5c 24 28 e8 1b 0d 03 00 48 8d 05 4a ca 8a 00 bb 02 00 00 00 e8 0a 0d 03 00 e8 05 08 03 00 48 8b 74 24 70 4c 8b 44 24 50 e9 b8 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DB_2147935667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DB!MTB"
        threat_id = "2147935667"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 8b 77 08 8b 57 10 48 8b 4f 18 44 8b 47 20 4c 8b 4f 28 8b 3f e8 5a e4 80 00 83 f8 ff 75 0b e8 12 e3 80 00 48 63 00 48 f7 d8}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 f9 04 7d 27 48 89 4c 24 18 48 c1 e1 04 48 8b 34 01 48 8b 3c 19 48 8b 4c 08 08 48 89 f0 48 89 fb e8 d7 70 f9 ff 84 c0 75 c3 eb b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CX_2147935668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CX!MTB"
        threat_id = "2147935668"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c3 01 d1 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f4 03 00 aa f3 03 08 aa 08 5c c0 39 a8 ?? ?? ?? 09 1d 00 12 e9 ?? ?? ?? 08 1d 40 92}  //weight: 1, accuracy: Low
        $x_1_2 = {89 a2 40 a9 0a f9 40 92 55 05 00 d1 3f 01 15 eb a1 ?? ?? ?? e9 ef 7d b2 5f 01 09 eb a0 ?? ?? ?? 13 fd 78 d3 96 02 40 f9 a8 01 80 92 e8 ff e7 f2 bf 02 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DE_2147935671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DE!MTB"
        threat_id = "2147935671"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 43 01 d1 f6 57 02 a9 f4 4f 03 a9 fd 7b 04 a9 fd 03 01 91 f3 03 08 aa 08 5c 40 39 09 1d 00 13 0a 04 40 f9 3f 01 00 71 48 b1 88 9a c8 ?? ?? ?? f4 03 00 aa 7f 7e 00 a9 01 fd 41 d3 7f 0a 00 f9 e0 03 13 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {08 00 80 52 15 00 80 52 7f 7e 00 a9 7f 0a 00 f9 89 5e 40 39 2a 1d 00 13 8b 32 40 a9 5f 01 00 71 74 b1 94 9a 89 b1 89 9a 96 02 09 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CY_2147935858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CY!MTB"
        threat_id = "2147935858"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 8b 1f 48 89 37 48 85 db 74 16 48 89 df e8 65 00 00 00 48 89 df 48 83 c4 08 5b 5d e9 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 f0 48 c1 e8 3e 75 1a 48 89 f3 48 8d 3c b5 00 00 00 00 e8 1b 03 00 00 48 89 da 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DF_2147936160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DF!MTB"
        threat_id = "2147936160"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 e0 07 00 f9 86 00 00 94 e8 07 40 f9 01 01 40 f9 1f 01 00 f9 10 00 00 94 e8 07 40 f9 08 05 40 f9 00 01 3f d6 e0 23 00 91 0d 00 00 94 00 00 80 d2 fd 7b 42 a9 f4 4f 41 a9 ff c3 00 91 c0 03 5f d6}  //weight: 1, accuracy: High
        $x_1_2 = {fc 6f bd a9 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 09 36 82 52 90 00 00 90 10 22 40 f9 00 02 3f d6 ff 07 40 d1 ff c3 06 d1 01 00 00 90 21 10 07 91 a0 a3 00 d1 d7 0a 00 94 01 00 00 f0 21 cc 27 91 a0 03 01 d1 bd 0a 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DG_2147937472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DG!MTB"
        threat_id = "2147937472"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {cb ff ff 97 a0 00 00 35 f3 07 00 f9 e0 23 00 91 04 00 00 94 fb ff ff 17}  //weight: 1, accuracy: High
        $x_1_2 = {ab 5e 40 39 6a 1d 00 13 ac 06 40 f9 5f 01 00 71 8b b1 8b 9a 1f 01 0b eb 02 01 00 54 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 4a 69 68 38 28 79 2a b8 08 05 00 91 f3 ff ff 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DH_2147937473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DH!MTB"
        threat_id = "2147937473"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f0 48 8b 7d f0 48 89 7d e8 e8 a7 27 87 00 48 8b 7d e8 48 89 45 e0 e8 5a fe ff ff 48 8b 75 e0 48 8b 7d e8 48 01 c6 e8 4a 29 87 00 48 89 45 f8 48 8b 45 f8 48 83 c4 20 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 20 48 89 7d f0 48 8b 7d f0 48 89 7d e0 e8 f7 27 87 00 48 8b 7d e0 48 89 c6 e8 ab 29 87 00 48 89 45 e8 e9 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DI_2147937714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DI!MTB"
        threat_id = "2147937714"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 37 40 f6 c6 01 74 06 49 8b 7f 08 eb 04 89 f7 d1 ef 48 39 f9 73 19 48 89 c7 40 f6 c6 01 74 04 49 8b 7f 10}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 89 f8 0f b6 0f f6 c1 01 75 07 48 ff c0 d1 e9 eb 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DP_2147940014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DP!MTB"
        threat_id = "2147940014"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 f0 48 83 e0 f8 48 83 c0 08 4d 89 f4 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 c9 00 00 00 48 89 43 10 49 83 cc 01 4c 89 23 4c 89 73 08 48 89 c3 48 89 df 4c 89 fe 4c 89 f2}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 54 53 49 89 f7 48 89 fb 48 89 f7 e8 3d 01 00 00 48 83 f8 f8 73 6c 49 89 c6 48 83 f8 17 73 10 43 8d 04 36 88 03 48 ff c3 4d 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DR_2147940016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DR!MTB"
        threat_id = "2147940016"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 05 00 11 6b 1d 40 92 ec 1f 40 f9 8d 69 6b 38 a9 01 09 0b 2e 1d 40 92 8f 69 6e 38 8f 69 2b 38 8d 69 2e 38 ec 1f 40 f9 8d 69 6b 38 8e 69 6e 38 cd 01 0d 0b ad 1d 40 92 8c 69 6d 38 ed 07 40 f9 ac 69 28 38 08 05 00 91 5f 01 08 eb}  //weight: 1, accuracy: High
        $x_1_2 = {ea 1f 40 f9 4b 69 69 38 ec 13 40 f9 8c 69 69 38 68 01 08 0b 08 01 0c 0b 0c 1d 40 92 4d 69 6c 38 4d 69 29 38 4b 69 2c 38 29 05 00 91 3f 01 04 f1 81 fe ff 54 ff 02 18 eb 40 03 00 54 08 00 80 d2 09 00 80 52 0b 00 80 d2 bf 06 00 f1 aa 86 9f 9a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DJ_2147940730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DJ!MTB"
        threat_id = "2147940730"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e0 48 8b 45 f0 48 89 45 e8 e8 ab 7f 52 00 48 89 c1 48 8b 45 e8 48 39 c8 0f 83 05 00 00 00 e9 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 7d f8 e8 8b 95 52 00 48 83 c4 10 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DL_2147940731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DL!MTB"
        threat_id = "2147940731"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 7d b0 8b 45 a0 89 45 c8 8b 45 cc c1 e0 04 8b 4d c8 09 c8 88 45 c7 0f be 75 c7 e8 5f a9 52 00 e9 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 20 48 89 7d f0 48 8b 7d f0 48 89 7d e0 e8 97 7e 52 00 48 8b 7d e0 48 89 c6 e8 4b 80 52 00 48 89 45 e8 e9 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DM_2147940732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DM!MTB"
        threat_id = "2147940732"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 7d f8 e8 cb 2d 76 00 48 83 c4 10 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d bd a8 bb ff ff e8 40 2c 32 00 88 85 fc e4 fe ff eb 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DO_2147940733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DO!MTB"
        threat_id = "2147940733"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 8b 7d f8 48 89 7d f0 e8 b7 79 94 00 a8 01 0f 85 05 00 00 00 e9 12 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 7d d8 e8 f8 79 94 00 48 03 45 e8 48 89 45 f8 48 8b 45 f8 48 83 c4 30 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DQ_2147940734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DQ!MTB"
        threat_id = "2147940734"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e0 48 8b 45 f0 48 89 45 e8 e8 ab 2b 76 00 48 89 c1 48 8b 45 e8 48 39 c8 73 02 eb 05}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 89 c6 48 8d 7d a8 ba 10 00 00 00 e8 b2 41 76 00 48 89 85 60 ff ff ff eb 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DS_2147940735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DS!MTB"
        threat_id = "2147940735"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 e0 07 00 f9 00 00 00 d0 00 f4 15 91 86 00 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {e0 0b 40 f9 a8 43 5b b8 08 21 00 71 a8 43 1b b8 a8 83 5b b8 a9 43 5b b8 08 29 c9 1a 08 1d 00 12 e8 bf 00 39 e1 bf c0 39 6a 0a 00 94 01 00 00 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DT_2147940736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DT!MTB"
        threat_id = "2147940736"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 8b 7d f8 48 89 7d f0 e8 77 1f 00 00 a8 01 75 02 eb 0f}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 7d f0 e8 98 1f 00 00 48 89 45 e8 eb 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DW_2147942302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DW!MTB"
        threat_id = "2147942302"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 fb f8 73 50 48 89 d8 48 83 e0 f8 48 83 c0 08 49 89 dc 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 a2 1d 00 00 49 89 47 10 49 83 cc 01 4d 89 27 49 89 5f 08 49 89 c7}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 f0 48 83 e0 f8 48 83 c0 08 4d 89 f7 49 83 cf 07 49 83 ff 17 4c 0f 44 f8 49 ff c7 4c 89 ff e8 bb 0e 00 00 49 83 cf 01 4c 89 3b 48 89 43 10 4c 89 73 08 48 83 c4 08 5b 41 5e 41 5f 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DY_2147942312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DY!MTB"
        threat_id = "2147942312"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c3 02 d1 fd 7b 0a a9 fd 83 02 91 e8 17 00 f9 a8 83 1f f8 a0 03 1f f8 a8 63 00 d1 e8 1b 00 f9 a1 83 1e f8 a2 03 1e f8 a3 83 1d f8 a4 03 1d f8 a0 03 5f f8 a8 fc ff 97 a0 83 1c f8 08 00 80 52 e8 17 00 b9 08 01 00 12 08 01 00 12 a8 73 1c 38 a0 83 5c f8 21 00 80 d2 57 01 00 94 e8 17 40 b9 e0 0f 00 f9 a1 83 5c f8 e0 43 01 91 e0 13 00 f9 02 01 00 12}  //weight: 1, accuracy: High
        $x_1_2 = {e8 5b 40 f9 00 41 00 91 99 fd ff 97 8c 01 00 94 a0 03 15 f8 a8 03 55 f8 08 01 40 f9 e8 23 00 f9 a0 23 02 d1 e0 27 00 f9 8e 01 00 94 e8 23 40 f9 e9 03 00 aa e0 27 40 f9 28 01 00 f9 93 01 00 94 7f 01 00 94 e8 03 00 aa e0 5b 40 f9 a9 03 55 f8 28 01 00 f9 a8 03 55 f8 e8 2b 00 f9 a1 03 59 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DU_2147942780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DU!MTB"
        threat_id = "2147942780"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 8a 3c 11 40 30 c7 40 80 f7 07 40 88 ?? ?? ?? ?? ?? ?? 69 c0 ?? ?? 00 00 48 89 c7 48 0f af fe 48 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DK_2147943313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DK!MTB"
        threat_id = "2147943313"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 1f 40 00 55 48 89 e5 53 50 e8 43 04 00 00 85 c0 75 07 48 83 c4 08 5b 5d c3 89 c7 89 c3 e8 e1 f9 ff ff 48 8d 35 9a 19 00 00 48 8d 15 29 1c 00 00 31 ff 48 89 c1 41 89 d8 31 c0 e8 d4 f5 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {89 c7 89 c3 e8 b1 fa ff ff 48 8d 35 6a 1a 00 00 48 8d 15 b8 1c 00 00 31 ff 48 89 c1 41 89 d8 31 c0 e8 a4 f6 ff ff 0f 1f 40 00 55 48 89 e5 53 50 e8 cd 04 00 00 a9 ef ff ff ff 75 0c 85 c0 0f 94 c0 48 83 c4 08 5b 5d c3 89 c7 89 c3 e8 69 fa ff ff 48 8d 35 22 1a 00 00 48 8d 15 8f 1c 00 00 31 ff 48 89 c1 41 89 d8 31 c0 e8 5c f6 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EC_2147944190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EC!MTB"
        threat_id = "2147944190"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 5d 80 0f 1f 00 43 8b 04 27 43 2b 04 2f 41 33 06 0f be f0 48 89 df}  //weight: 2, accuracy: High
        $x_1_2 = {48 89 c2 4c 09 e2 48 c1 ea 20 74 ?? 31 d2 49 f7 f4 48 89 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EE_2147946805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EE!MTB"
        threat_id = "2147946805"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 28 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 1d 40 f6 c6 02 0f 85 e4 00 00 00 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 48 d1 ee eb 1c}  //weight: 1, accuracy: High
        $x_1_2 = {45 31 ff 45 31 e4 eb 14 66 66 66 2e 0f 1f 84 00 00 00 00 00 49 83 c4 02 49 83 c7 fe 45 0f b6 2e 41 f6 c5 01 75 0e 49 d1 ed 4d 39 ec 73 79 48 8b 75 b8 eb 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EF_2147946806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EF!MTB"
        threat_id = "2147946806"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e3 06 41 0b 58 14 41 8d 44 24 06 41 83 fc 02 7c 36 41 83 c4 fe 44 89 e6 c1 ee 03 ff c6 31 d2 41 83 fc 18 73 2a 41 89 c4 eb 78 89 c8 31 d2 f7 f7 89 d6 49 8b 06 48 8b 04 f0 48 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 cf 48 c1 ef 3e 48 31 cf 48 0f af f8 48 01 f7 48 ff cf 48 89 bc f5 e8 f5 ff ff 48 81 fe 38 01 00 00 74 2a 48 8d 4a 01 49 89 f8 49 c1 e8 3e 49 31 f8 4c 0f af c0 4c 01 c1 49 01 f0 4c 89 84 f5 f0 f5 ff ff 48 83 c2 02 48 83 c6 02 eb b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EA_2147947804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EA!MTB"
        threat_id = "2147947804"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 83 00 91 e0 e3 00 91 9e fe ff 97 2b ff ff 97 f3 23 00 91 e8 23 00 91 e0 83 00 91 a1 23 01 d1 51 fe ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71 20 b1 93 9a 29 02 00 94 20 ff ff 97 e8 9f c1 39 e9 2b 40 f9 1f 01 00 71 e8 43 01 91 20 b1 88 9a 22 02 00 94 e8 7f c0 39}  //weight: 1, accuracy: High
        $x_1_2 = {ff 83 01 d1 eb 2b 02 6d e9 23 03 6d f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 fc 02 00 94 f3 a3 90 52 73 3d aa 72 08 7c 33 9b 09 fd 7f d3 08 fd 65 93 08 01 09 0b 94 0c 80 52 08 81 14 1b 09 fd 42 1e f2 02 00 94 08 7c 33 9b 09 fd 7f d3 08 fd 65 93 08 01 09 0b 08 81 14 1b 00 01 62 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DX_2147948603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DX!MTB"
        threat_id = "2147948603"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 03 00 aa e8 7f c0 39 a8 00 f8 36 e0 07 40 f9 47 01 00 94 02 00 00 14}  //weight: 1, accuracy: High
        $x_1_2 = {88 f2 7d 92 08 21 00 91 89 0a 40 b2 3f 5d 00 f1 08 01 89 9a 17 05 00 91 e0 03 17 aa 2b 01 00 94 f6 03 00 aa e8 02 41 b2 74 a2 00 a9 60 02 00 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_DZ_2147948604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.DZ!MTB"
        threat_id = "2147948604"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 7b bf a9 fd 03 00 91 00 01 80 52 84 00 00 94 71 00 00 94 21 05 00 f0 21 14 40 f9 22 05 00 f0 42 04 40 f9 87 00 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {ff 83 04 d1 fc 6f 0e a9 f6 57 0f a9 f4 4f 10 a9 fd 7b 11 a9 fd 43 04 91 13 00 80 d2 34 05 00 90 94 12 0f 91 bf 7f 3a a9 35 05 00 90 b5 12 1f 91 bf 03 1b f8 36 05 00 90 d6 12 17 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EB_2147948607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EB!MTB"
        threat_id = "2147948607"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 3b 48 c7 03 00 00 00 00 48 85 ff 74 09 5b 41 5e 5d e9 8e 14 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 bf 08 00 00 00 e8 82 02 00 00 48 89 c3 48 89 c7 e8 4d 02 00 00 48 8b 35 be f8 0b 00 48 8b 15 8f f8 0b 00 48 89 df e8 73 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_ED_2147948608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.ED!MTB"
        threat_id = "2147948608"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b 7e 08 48 85 ff 0f 84 69 02 00 00 4d 01 fd 31 db 45 31 e4 48 85 ff 0f 84 41 02 00 00 90}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb e8 1e 08 00 00 48 89 df 48 83 c4 08 5b 5d e9 1c 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EI_2147950395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EI!MTB"
        threat_id = "2147950395"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 79 60 b8 21 00 05 4b 21 00 03 4a 42 00 06 4b 42 00 04 4a 6f 6a 2d 38 70 6a 2e 38 61 6a 31 38 62 6a 20 38 29 11 00 f1 a1 fc ff 54 00 11 80 52 88 06 00 94 f6 03 00 aa a0 03 1a f8 08 00 00 d0 00 69 c2 3d 80 82 80 3c 60 06 42 ad 00 04 02 ad 60 06 43 ad 00 04 03 ad 60 06 40 ad 00 04 00 ad 60 06 41 ad 00 04 01 ad 1f 00 02 39 e0 03 13 aa 75 06 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {e3 fb ff 97 e8 83 00 91 e0 e3 00 91 52 fb ff 97 df fb ff 97 e8 23 00 91 e0 83 00 91 a1 23 01 d1 06 fb ff 97 da fb ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71 e8 23 00 91 20 b1 88 9a c2 05 00 94 d3 fb ff 97 e8 9f c1 39 e9 2b 40 f9 1f 01 00 71 e8 43 01 91 20 b1 88 9a bb 05 00 94 e8 7f c0 39 48 02 f8 37 e8 df c0 39 88 02 f8 37 e0 03 16 aa 85 05 00 94 e8 9f c1 39 c8 02 f8 37 e8 ff c1 39 08 03 f8 37 e8 5f c2 39 48 03 f8 37 a8 f3 d9 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EL_2147950401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EL!MTB"
        threat_id = "2147950401"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8d 41 01 48 c1 e8 03 49 f7 e7 48 d1 ea 48 69 c2 38 01 00 00 48 f7 d8 49 8d 3c 01 48 ff c7 89 fb 4d 8d b1 9c 00 00 00 4c 89 f0 48 c1 e8 03 49 f7 e7 49 8b 5c dd 00 4c 89 e0 f6 c3 01 0f 85 12 ff ff ff 31 c0 e9 0b ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 c2 48 c1 ea 1d 49 b9 55 55 55 55 05 00 00 00 4c 21 ca 48 31 c2 48 89 d0 48 c1 e0 11 48 bb 00 00 a6 ed ff 7f d6 71 48 21 d8 48 31 d0 48 89 c2 48 c1 e2 25 49 b9 00 00 00 00 e0 ee f7 ff 4c 21 ca 48 31 c2 48 89 d0 48 c1 e8 2b 48 31 d0 48 89 3d 0e 25 14 00 48 d3 c0 4c 31 c0 48 89 84 24 80 00 00 00 48 8b 84 24 80 00 00 00 f6 c1 07 74 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EH_2147951875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EH!MTB"
        threat_id = "2147951875"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ed 03 08 aa 08 05 00 91 1f e1 04 f1 e8 07 8d 9a ee 7a 6d f8 ef 7a 68 f8 b0 71 02 91 11 fe 43 d3 31 7e da 9b 31 fe 41 d3 30 c2 0a 9b ce 81 61 92 f1 75 7f 92 f0 7a 70 f8 ff 01 00 72 0f 13 9f 9a 2e 02 0e aa ef 01 10 ca ee 05 4e ca 2f 77 4e 8a ef 01 0e ca 90 95 0f 8a e8 e2 04 f9 10 46 0f ca 10 02 0e ca 10 fe 6b d3}  //weight: 1, accuracy: High
        $x_1_2 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa a1 06 00 b4 f4 03 01 aa 28 fc 7d d3 08 0c 00 b5 80 f2 7d d3 b3 01 00 94 e8 03 00 aa 60 02 40 f9 68 02 00 f9 40 00 00 b4 ab 01 00 94 08 00 80 d2 74 06 00 f9 69 02 40 f9 3f 79 28 f8 08 05 00 91 9f 02 08 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_EM_2147951885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.EM!MTB"
        threat_id = "2147951885"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 ff 81 39 69 01 f8 b7 69 16 00 34 0a 69 69 38 5f 29 00 71 44 19 4d 7a e1 15 00 54 29 05 00 d1 e9 ff 01 39 ea a3 01 91 5f 69 29 38 f5 ff ff 17 e9 3b 40 f9 e9 14 00 b4 ea 37 40 f9 49 01 09 8b 29 f1 5f 38 3f 29 00 71 24 19 4d 7a 21 14 00 54 ea a7 46 a9 29 05 00 d1 e9 3b 00 f9 5f 69 29 38}  //weight: 1, accuracy: High
        $x_1_2 = {f9 3f 41 39 28 1f 00 13 f3 23 40 f9 1f 01 00 71 78 b2 99 9a 58 0a 00 b4 e9 ff 44 39 28 1d 00 13 ea 9b 40 f9 1f 01 00 71 49 b1 89 9a fa 1f 40 f9 1f 03 09 eb 81 01 00 54 29 1f 00 13 3f 01 00 71 e9 e3 00 91 40 b3 89 9a e9 97 40 f9 1f 01 00 71 e8 a3 04 91 21 b1 88 9a e2 03 18 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

