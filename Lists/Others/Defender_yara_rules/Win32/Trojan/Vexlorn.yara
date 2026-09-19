rule Trojan_Win32_Vexlorn_DA_2147978115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vexlorn.DA!MTB"
        threat_id = "2147978115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vexlorn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 8d 64 24 a0 4d 3b 66 10 0f 86 ?? ?? ?? ?? 55 48 89 e5 48 81 ec d8 00 00 00 48 8d 05 1f 72 12 00 e8 ?? ?? ?? ?? 48 b9 00 e4 0b 54 02 00 00 00 48 89 48 28 48 8b 1d b5 9b a6 00 48 8b 0d b6 9b a6 00 e8 ?? ?? ?? ?? 48 85 db 75 ?? 48 8b 48 40 48 8b 58 48 48 85 c9 74 25 48 8b 51 08 48 8b 35 7c be a6 00 48 8b 3e 8b 49 10 e9}  //weight: 10, accuracy: Low
        $x_1_2 = "json:\"steal\"" ascii //weight: 1
        $x_1_3 = "runtime.traceLocker.ProcSteal" ascii //weight: 1
        $x_1_4 = "github.com/ethereum/go-ethereum/common.(*Address).checksumHex" ascii //weight: 1
        $x_1_5 = "crypto/aes.NewCipher" ascii //weight: 1
        $x_1_6 = "crypto/cipher.NewGCM" ascii //weight: 1
        $x_1_7 = "/expectexpectd/configpdf*pdfcmd.exelib.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vexlorn_DB_2147978506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vexlorn.DB!MTB"
        threat_id = "2147978506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vexlorn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[AppDataFolder]SoftwareTools\\PDF Municipal 7.3.4\\install" ascii //weight: 10
        $x_10_2 = "3208CBC\\PDF Municipal.7z" ascii //weight: 10
        $x_10_3 = "\\\\?\\C:\\TEMP\\3208CBC" ascii //weight: 10
        $x_10_4 = "PDF Municipal.ini" ascii //weight: 10
        $x_1_5 = "CreateProcessW" ascii //weight: 1
        $x_1_6 = "ShellExecuteW" ascii //weight: 1
        $x_1_7 = "InternetOpenW" ascii //weight: 1
        $x_1_8 = "HttpOpenRequestW" ascii //weight: 1
        $x_1_9 = "HttpSendRequestW" ascii //weight: 1
        $x_1_10 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

