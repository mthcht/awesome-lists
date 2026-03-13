rule Ransom_Win64_BadJoke_AMTB_2147961823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BadJoke!AMTB"
        threat_id = "2147961823"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEER HACKER" ascii //weight: 1
        $x_1_2 = "Your PC is Pwned DEER" ascii //weight: 1
        $x_1_3 = "DEER WAS HERE! Your system is pwned!" ascii //weight: 1
        $x_1_4 = "Your files have been encrypted. Pay 1 BTC to restore access" ascii //weight: 1
        $x_1_5 = "Deer is eating the registry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BadJoke_AR_2147964706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BadJoke.AR!AMTB"
        threat_id = "2147964706"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Installing backdoor..." ascii //weight: 1
        $x_1_2 = "[+] Ransomware deploying..." ascii //weight: 1
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_4 = "DEPLOYING RANSOMWARE PAYLOAD" ascii //weight: 1
        $x_1_5 = "INITIATING DATA DESTRUCTION SEQUENCE" ascii //weight: 1
        $x_1_6 = "Bitcoin address for payment: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" ascii //weight: 1
        $x_1_7 = "Hacking Group \"Shadow Syndicate\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

