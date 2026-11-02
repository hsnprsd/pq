/* Generates a synthetic Firefox NSS fixture, never real credentials. */
#include <nss.h>
#include <pk11pub.h>
#include <pk11sdr.h>
#include <nssb64.h>
#include <secitem.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3 || NSS_InitReadWrite(argv[1]) != SECSuccess) return 1;
    const char *password = strcmp(argv[2], "primary") == 0 ? "fixture primary password" : "";
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (!slot || PK11_InitPin(slot, NULL, password) != SECSuccess) return 2;
    if (PK11_CheckUserPassword(slot, password) != SECSuccess) return 3;
    const char *values[] = {"fixture-user", "fixture-password"};
    for (int i = 0; i < 2; i++) {
        SECItem key = {0}, input = {siBuffer, (unsigned char *) values[i], strlen(values[i])}, output = {0};
        if (PK11SDR_Encrypt(&key, &input, &output, NULL) != SECSuccess) return 4;
        char *encoded = NSSBase64_EncodeItem(NULL, NULL, 0, &output);
        if (!encoded) return 5;
        for (char *p = encoded; *p; p++) if (*p != '\r' && *p != '\n') putchar(*p);
        putchar('\n');
        PORT_Free(encoded);
        SECITEM_ZfreeItem(&output, PR_FALSE);
    }
    PK11_FreeSlot(slot);
    return NSS_Shutdown() == SECSuccess ? 0 : 6;
}
