rule Trojan_Linux_Kaiji_A_2147764476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.A!MTB"
        threat_id = "2147764476"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Allowlist" ascii //weight: 1
        $x_1_2 = ".RNG" ascii //weight: 1
        $x_1_3 = "fakeLocker" ascii //weight: 1
        $x_1_4 = "KeyLogWriter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Kaiji_A_2147764476_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.A!MTB"
        threat_id = "2147764476"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/id.services.conf" ascii //weight: 1
        $x_1_2 = "os/user.lookupUserId" ascii //weight: 1
        $x_1_3 = "/root/src/ddos/kill.go" ascii //weight: 1
        $x_1_4 = "ddos.getIpFromAddr" ascii //weight: 1
        $x_1_5 = "crypto/cipher.NewCFBDecrypter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_Kaiji_B_2147793495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.B!MTB"
        threat_id = "2147793495"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sshattack.func1" ascii //weight: 2
        $x_2_2 = "ddos.Udpflooda" ascii //weight: 2
        $x_1_3 = "os/user.lookupUserId" ascii //weight: 1
        $x_1_4 = "ddos.Runshellkill" ascii //weight: 1
        $x_1_5 = "crypto/cipher.NewCFBDecrypter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Kaiji_C_2147832060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.C!MTB"
        threat_id = "2147832060"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "main.CVE" ascii //weight: 10
        $x_10_2 = ".rng" ascii //weight: 10
        $x_10_3 = "forceattempthttp" ascii //weight: 10
        $x_1_4 = "syscall.accept" ascii //weight: 1
        $x_1_5 = "syscall.connect" ascii //weight: 1
        $x_1_6 = "syscall.sendfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Kaiji_D_2147911019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.D!MTB"
        threat_id = "2147911019"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 00 00 06 00 00 00 00 3c 14 00 25 02 9c a0 2d 66 94 e7 10 0c 02 55 f6 00 00 00 00 3c 17 00 28}  //weight: 1, accuracy: High
        $x_1_2 = {15 80 ff ed 00 00 00 00 ff aa 00 50 ff a1 00 40 ff a9 00 08 ff a8 00 10 ff ab 00 18 0c 00 48 ce 00 00 00 00 93 a1 00 20 14 20 00 0a 00 00 00 00 df a1 00 40 df a3 00 58 df a4 00 38 93 a5 00 2f df a6 00 88 df a7 00 60 df a8 00 70 10 00 ff da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Kaiji_E_2147928899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.E!MTB"
        threat_id = "2147928899"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 10 9a e5 01 00 5d e1 33 00 00 9a 10 e0 2d e5 d4 00 9f e5 04 00 8d e5 0a 2e 00 eb 08 30 9d e5 05 00 a0 e3 04 00 83 e5 c0 10 9f e5 00 10 83 e5 bc 10 9f e5 08 10 83 e5 14 00 83 e5 b4 00 9f e5 10 00 83 e5 b0 00 9f e5 18 00 83 e5 02 00 a0 e3}  //weight: 1, accuracy: High
        $x_1_2 = {9e e6 00 eb c4 03 9f e5 04 00 8d e5 10 10 a0 e3 08 10 8d e5 f1 e8 00 eb 30 00 9d e5 04 00 8d e5 28 00 9d e5 01 00 40 e2 08 00 8d e5 eb e8 00 eb 9c 03 9f e5 04 00 8d e5 20 10 a0 e3 08 10 8d e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Kaiji_F_2147929990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.F!MTB"
        threat_id = "2147929990"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Dns_Url" ascii //weight: 1
        $x_1_2 = "main.Killsh" ascii //weight: 1
        $x_1_3 = "/client/linux/killcpu.go" ascii //weight: 1
        $x_1_4 = "main.getwebwalk" ascii //weight: 1
        $x_1_5 = "main.attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Kaiji_G_2147935643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kaiji.G!MTB"
        threat_id = "2147935643"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kaiji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Killcpu" ascii //weight: 1
        $x_1_2 = "main.terminalrun" ascii //weight: 1
        $x_1_3 = "main.Proxyhandle" ascii //weight: 1
        $x_1_4 = "main.(*Allowlist).Add" ascii //weight: 1
        $x_1_5 = "main.Ares_Tcp_Send" ascii //weight: 1
        $x_1_6 = "/client/linux/attack.go" ascii //weight: 1
        $x_1_7 = "main.Dns_Url" ascii //weight: 1
        $x_1_8 = "main.Ares_ipspoof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

