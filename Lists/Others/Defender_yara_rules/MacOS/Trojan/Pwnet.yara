rule Trojan_MacOS_Pwnet_A_2147745013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Pwnet.A!MTB"
        threat_id = "2147745013"
        type = "Trojan"
        platform = "MacOS: "
        family = "Pwnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vlone.cc" ascii //weight: 2
        $x_1_2 = "/private/.discord/xmr.zip" ascii //weight: 1
        $x_1_3 = "installMinerEv" ascii //weight: 1
        $x_1_4 = "pwnednet/pwnednet/" ascii //weight: 1
        $x_1_5 = "LoadMinerEv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Pwnet_B_2147746257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Pwnet.B!MTB"
        threat_id = "2147746257"
        type = "Trojan"
        platform = "MacOS: "
        family = "Pwnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Desktop/pwnednet/pwnednet/pwnednet/" ascii //weight: 1
        $x_1_2 = "com.dynamsoft.WebHelper" ascii //weight: 1
        $x_1_3 = "/private/.trash/.assets/helper.zip" ascii //weight: 1
        $x_1_4 = "installMinerEv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Pwnet_C_2147747902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Pwnet.C!MTB"
        threat_id = "2147747902"
        type = "Trojan"
        platform = "MacOS: "
        family = "Pwnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 7d d4 00 0f 9f c0 34 ff 24 01 0f b6 c8 48 63 d1 48 83 fa 00 0f 84 1f 00 00 00 48 8d 3d a8 0f 00 00 48 8d 35 ad 0f 00 00 ba 3a 00 00 00 48 8d 0d 18 10 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "injector" ascii //weight: 1
        $x_1_3 = "Csgo/Csgo Cheats/Injectors/osxinj-fixed-master/osxinj/mach_inject.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Pwnet_D_2147748068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Pwnet.D!MTB"
        threat_id = "2147748068"
        type = "Trojan"
        platform = "MacOS: "
        family = "Pwnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Injected" ascii //weight: 1
        $x_1_2 = "/Downloads/GO-SX-Internal-Lite-master/osxinj/mach_inject" ascii //weight: 1
        $x_1_3 = {8a 85 c7 fe ff ff 34 ff 24 01 0f b6 c8 48 63 d1 48 83 fa 00 0f 84 ?? ?? ?? ?? 48 8d 3d ab 11 00 00 48 8d 35 b0 11 00 00 48 8d 0d 16 12 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Pwnet_D_2147748068_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Pwnet.D!MTB"
        threat_id = "2147748068"
        type = "Trojan"
        platform = "MacOS: "
        family = "Pwnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "osxinj/mach_inject.c" ascii //weight: 1
        $x_1_2 = "./osxinj [proc_name] [lib]" ascii //weight: 1
        $x_1_3 = "./osxinj [pid] [lib]" ascii //weight: 1
        $x_1_4 = "injector.cpp" ascii //weight: 1
        $x_1_5 = {2f 6f 73 78 69 6e 6a 2e 62 75 69 6c 64 2f [0-7] 2f 6f 73 78 69 6e 6a 2e 62 75 69 6c 64}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 67 6f 73 78 69 6e 6a 2e 62 75 69 6c 64 2f [0-7] 2f 67 6f 73 78 69 6e 6a 2e 62 75 69 6c 64}  //weight: 1, accuracy: Low
        $x_1_7 = "please run me as root" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_Pwnet_E_2147750948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Pwnet.E!MTB"
        threat_id = "2147750948"
        type = "Trojan"
        platform = "MacOS: "
        family = "Pwnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Desktop/osxinj-master/osxinj/mach_inject.c" ascii //weight: 2
        $x_1_2 = "./osxinj" ascii //weight: 1
        $x_1_3 = "please run me as root" ascii //weight: 1
        $x_1_4 = {49 6e 6a 65 63 74 6f 72 90 01 02 67 65 74 50 72 6f 63 65 73 73 42 79 4e 61 6d 65 45 50 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

