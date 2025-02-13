rule Trojan_Win32_Metasploit_CBU_2147851495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Metasploit.CBU!MTB"
        threat_id = "2147851495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d4 01 d0 0f b6 00 31 c1 89 ca 8d 8d 97 fb ff ff 8b 45 d0 01 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Metasploit_AMAA_2147898995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Metasploit.AMAA!MTB"
        threat_id = "2147898995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 eb fc 31 43 10 03 43 10 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Metasploit_PAEV_2147913708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Metasploit.PAEV!MTB"
        threat_id = "2147913708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Allocating memory in process" ascii //weight: 1
        $x_1_2 = "Writing shellcode to process" ascii //weight: 1
        $x_1_3 = "Shellcode is written to memory" ascii //weight: 1
        $x_1_4 = "Writing fake subclass to process" ascii //weight: 1
        $x_1_5 = "Triggering shellcode....!!!" ascii //weight: 1
        $x_1_6 = "Press enter to unhook the function and exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Metasploit_PAFV_2147924782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Metasploit.PAFV!MTB"
        threat_id = "2147924782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "You seem to have active VMs running, please stop them before running this to prevent corruption of any saved data of the VMs." ascii //weight: 2
        $x_1_2 = "VirtualBox process active" ascii //weight: 1
        $x_2_3 = ".\\exploit.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

