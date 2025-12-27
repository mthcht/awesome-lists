rule Trojan_Win64_TofuStation_A_2147951090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.A!dha"
        threat_id = "2147951090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppUISvc" wide //weight: 1
        $x_1_2 = {00 77 6d 6f 6e 73 76 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4b 72 62 4d 61 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_TofuStation_B_2147951091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.B!dha"
        threat_id = "2147951091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c2 83 22 f1 b1 41 67 0e 20 fc 5b 81 f4 27 5a 2f 6f}  //weight: 1, accuracy: High
        $x_1_2 = {fa d4 d7 aa 95 9b 70 0f 25 06 b3 1e 4e 46 86 f4 ba}  //weight: 1, accuracy: High
        $x_1_3 = {08 82 bf 4d fa cb a4 33 63 5b e2 3d bf 19 e3 9c 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_TofuStation_C_2147951092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.C!dha"
        threat_id = "2147951092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" ascii //weight: 1
        $x_1_2 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43" ascii //weight: 1
        $x_1_3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36 Edg/91.0.864.37" ascii //weight: 1
        $x_1_4 = {00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 45 00 6e 00 68 00 61 00 6e 00 63 00 65 00 64 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 20 00 76 00 31 00 2e 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 45 00 6e 00 68 00 61 00 6e 00 63 00 65 00 64 00 20 00 52 00 53 00 41 00 20 00 61 00 6e 00 64 00 20 00 41 00 45 00 53 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 74 00 6f 00 6b 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 00 63 00 65 00 72 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_TofuStation_D_2147951093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.D!dha"
        threat_id = "2147951093"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@jnsaoe@@" ascii //weight: 1
        $x_1_2 = "@w17gd92@@" ascii //weight: 1
        $x_1_3 = "@fhuq3o9@@" ascii //weight: 1
        $x_1_4 = "@vem023q@@" ascii //weight: 1
        $x_1_5 = "?AVuasrgf98237a@" ascii //weight: 1
        $x_1_6 = "?AVsldffh@w17gd92@" ascii //weight: 1
        $x_1_7 = "?AVs786d@fhuq3o9@" ascii //weight: 1
        $x_1_8 = "?AVj923qwm1@fhuq3o9@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_TofuStation_E_2147951094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.E!dha"
        threat_id = "2147951094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?AViusb37q@" ascii //weight: 1
        $x_1_2 = "?AVfh297qap@" ascii //weight: 1
        $x_1_3 = "?AVsdcnjwa@" ascii //weight: 1
        $x_1_4 = "?AVwfh82gq@" ascii //weight: 1
        $x_1_5 = "?AVlke9872e@" ascii //weight: 1
        $x_1_6 = "?AVlkbvuo@" ascii //weight: 1
        $x_1_7 = "?AVbsdf72lo@" ascii //weight: 1
        $x_1_8 = "?AVunb60a@" ascii //weight: 1
        $x_1_9 = "?AVium23wng@" ascii //weight: 1
        $x_1_10 = "?AVzc8234a@" ascii //weight: 1
        $x_1_11 = "?AVnew928u@" ascii //weight: 1
        $x_1_12 = "?AVbnw1oel@" ascii //weight: 1
        $x_1_13 = "?AVql1298h@" ascii //weight: 1
        $x_1_14 = "?AVadnqw@" ascii //weight: 1
        $x_1_15 = "?AVoien49j@" ascii //weight: 1
        $x_1_16 = "?AVno234re@" ascii //weight: 1
        $x_1_17 = "?AVbnar54g@" ascii //weight: 1
        $x_1_18 = "?AVcnqwpo@" ascii //weight: 1
        $x_1_19 = "?AVnab39hk@" ascii //weight: 1
        $x_1_20 = "?AVka9231s@" ascii //weight: 1
        $x_1_21 = "?AVqp34sd@" ascii //weight: 1
        $x_1_22 = "?AVasdfawgwer@" ascii //weight: 1
        $x_1_23 = "?AVhasoi89@" ascii //weight: 1
        $x_1_24 = "?AVwoirn271@" ascii //weight: 1
        $x_1_25 = "?AVnace821@" ascii //weight: 1
        $x_1_26 = "?AVbsaduf2@" ascii //weight: 1
        $x_1_27 = "?AVndof0q7@" ascii //weight: 1
        $x_1_28 = "?AVw8r23rh@" ascii //weight: 1
        $x_1_29 = "?AVxcvb0u9h@" ascii //weight: 1
        $x_1_30 = "?AVj2183a@" ascii //weight: 1
        $x_1_31 = "?AVs09cv@" ascii //weight: 1
        $x_1_32 = "?AViowu93hq@" ascii //weight: 1
        $x_1_33 = "?AVmsd1h3@" ascii //weight: 1
        $x_1_34 = "?AVsq083rt@" ascii //weight: 1
        $x_1_35 = "?AVnar89376@" ascii //weight: 1
        $x_1_36 = "?AVoidfed@" ascii //weight: 1
        $x_2_37 = "?AVAES256Cipher@" ascii //weight: 2
        $x_2_38 = "?AVGammaCryptoStrategy@" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_TofuStation_F_2147951095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.F!dha"
        threat_id = "2147951095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Init: Kernel initialised" ascii //weight: 1
        $x_1_2 = "Init: Setting settnigs" ascii //weight: 1
        $x_1_3 = "ServiceWorkerThread: Init is successfull, entring main loop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_TofuStation_G_2147951096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TofuStation.G!dha"
        threat_id = "2147951096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TofuStation"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ". Current Status:" ascii //weight: 1
        $x_1_2 = "C:\\service_log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

