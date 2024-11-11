// Inspired in https://learn.microsoft.com/en-us/previous-versions/iis/smooth-streaming-client/walkthrough-creating-a-request-level-http-module-by-using-native-code
// Modified with https://stackoverflow.com/questions/71376090/iis-native-module-websocket
// Follows this recomendation https://iis-blogs.azurewebsites.net/jennylaw/iis-and-websockets
#include "pch.h"

#define _WINSOCKAPI_
#include <stdio.h>
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
#include <iiswebsocket.h>
#include <fstream>
#include <iostream>
#include <chrono>
#include <time.h>
#include <Wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib") 

#include "hmac_sha256.h"

// To activate the debug mode in a temporal output define DEBUG_TO_TEMP 
#define TEST
#define DEBUG_TO_TEMP 
#ifdef DEBUG_TO_TEMP
char szDebugFile[21] = "c://temp//output.txt" ;
std::ofstream outputFile;
#endif


// Timer Class
// Extract from: https://stackoverflow.com/questions/71598718/timer-with-stdthread
#include <thread>
#include <chrono>
#include <functional>

class Timer
{
public:
    ~Timer();
    Timer() noexcept;

    typedef std::chrono::milliseconds Interval;
    typedef std::function<void(char *id, char *callback)> Timeout;

public:
    void start(const Interval& interval, const Timeout& timeout, char* szWebSockedId, char *szCallbackURL);
    void stop();

private:
    std::thread mThread;    /** Timer thread */
    bool mRunning = false;  /** Timer status */
};

Timer::~Timer()
{
}

Timer::Timer() noexcept
{
}

void Timer::start(const Interval& interval, const Timeout& timeout, char* id, char* callback)
{
    /*mRunning = true;

    mThread = std::thread([&]()
        {
            while (mRunning == true)
            {
                std::this_thread::sleep_for(interval);

                // std::abort will be called here
                timeout(id, callback);
            }
        });
        */
    mRunning = true;
    mThread = std::thread([&]() {
        while (mRunning) {
            auto delta = std::chrono::steady_clock::now() + std::chrono::milliseconds(interval);
            timeout(id, callback);
            std::this_thread::sleep_until(delta);
        }
        });
    mThread.detach();
}

void Timer::stop()
{
    /*mRunning = false;
    mThread.join();*/

    mRunning = false;
    mThread.~thread();
}

// Some definitions

#define MAX_LENGTH_TOPIC 1000
#define MAX_LENGTH_SECRET 200
#define MAX_LENGTH_XAPIKEY MAX_LENGTH_SECRET 
#define MAX_LENGTH_CHALLENGE 255
#define MAX_LENGTH_CALLBACK MAX_LENGTH_TOPIC 


char szXAPIKey_Param[] = "webhook.x-api-key";
char szTopic_Param[] = "topic";

// Global variables to control the subscriptions and its state
struct NOTIFICATION
{
    char* dataPost; // Data to send to the subscriber
};

struct SUBSCRIPTION
{
    // When the subscriber unsubscribe a topic the subscription will be deleted
    char* szCallBackURL; // Hub.CallBack: URL del WebHook with socket Identifier and topic of client.
                         /* WebHook Identifier
    * A unique relation to a topic by a subscriber that indicates it should receive updates for that topic.
    * A subscription's unique key is the tuple (Topic URL, Subscriber Callback URL).
    * Subscriptions may (at the hub's decision) have expiration times akin to DHCP leases which must be periodically renewed.*/

    char* szTopic; // Hub.Topic: Topic o STA Request that the client to be subscribed. The SensorThings (STAplus) Topic that this WebHook is going to receive
    char* szSecret; // Hub.Secret: Key. The shared secret for the Hub to generate HMAC values
    
    char* szXAPIKey; // WebHook.X-API-Key WebHook site

    char* szChallenge;  //  hub.challenge: A hub-generated, random string that MUST be echoed by the subscriber to verify the subscription.
    int lease_seconds;  /* hub.lease_seconds: REQUIRED / OPTIONAL.The hub - determined number of seconds that the subscription will stay active before expiring,
                        measured from the time the verification request was made from the hub to the subscriber.
                        Hubs MUST supply this parameter when hub.mode is set to "subscribe".
                        This parameter MAY be present when hub.mode is "unsubscribe" and MUST be ignored by subscribers in that case.*/
    Timer tm;

    //char* xHubSignature; // MUST send a X-Hub-Signature header if the subscription was made with a hub.secret as described in Authenticated Content Distribution.    
                        /* If the subscriber supplied a value for hub.secret in their subscription request, the hub MUST generate an HMAC signature of the payload and
                        include that signature in the request headers of the content distribution request.
                        The X - Hub - Signature header's value MUST be in the form method=signature where method is one of the recognized algorithm names and
                        signature is the hexadecimal representation of the signature.
                        The signature MUST be computed using the HMAC algorithm [RFC6151] with the request body as the data and the hub.secret as the key.

                        When subscribers receive a content distribution request with the X-Hub-Signature header specified,
                        they SHOULD recompute the signature with the shared secret using the same method (provided in the X-Hub-Signature header) as the hub.
                        If the signature does not match, subscribers MUST locally ignore the message as invalid.*/
    

    size_t nNotifications = 0;
    size_t max_nNotificacions = 0;
#define INCR_NOTIFICACIONS 5

    struct NOTIFICATION* Notifications = NULL;
};

size_t nWSConnections = 0;
size_t max_nWSConnections = 0;
#define INCR_WSCONNECTION 2
struct WS_CONNECTION* WSConnections= NULL;

struct WS_CONNECTION
{
    char* szWebSocketId; // WebSocket identifier

    // One WS cna be subscribed to one more one topic

    size_t nSubscriptions = 0;
    size_t max_nSubscriptions = 0;
#define INCR_SUBSCRIPTIONS 5
    struct SUBSCRIPTION* Subscriptions = NULL;    
};


CRITICAL_SECTION SubscriptionsSection;

// General functions
char* stristr(const char* s, const char* find);
void* recalloc(void* block, size_t new_size, size_t old_size);
BYTE* stringToHexa(char* str_text);
char* deleteLastCharOfString(char* string, const char c);
char* strnzcpy(char* dest, const char* src, size_t maxlen);
int CharToUnicode(LPCSTR lpMultiByteStr, LPWSTR lpWideCharStr, size_t cchWideChar);
int CharToUTF8(LPCSTR CharStr, LPSTR UTF8Str, size_t cchUTF8Str);
BOOL ExpandAndCopyUTF8FromChar(LPSTR* UTF8Str, size_t* cchUTF8Str, const char* s);


// Query functions
char* GetCallBackURL(const char* name_topic_key, char* query, char* sz_WebSocketId);
char* GetQueryParameter(char* value, size_t value_size, const char* name, char* query);

// Functions related with subscriptions and notifications
struct WS_CONNECTION* GetMemoryWSConnectionIfNeeded(void);
void FreeMemoryAllWSConnections(void);
void FreeMemoryOfOneWSConnection(size_t i_connec);
struct WS_CONNECTION* GetWSConnection(char* szWebSocketId);
size_t PushNewWSConnection(char* szScriptName);

struct SUBSCRIPTION* GetMemoryForSubscriptionIfNeeded(struct WS_CONNECTION *ws);
void FreeMemoryOfOneSubscription(struct WS_CONNECTION* ws, size_t i_subs);
void FreeMemoryAllSubscriptions(struct WS_CONNECTION* ws);
size_t GetSubscriptionIndiceFromWSConnection(struct WS_CONNECTION* ws, char* szCallBackURL);
struct SUBSCRIPTION* GetSubscription(char* szWebSocketId, char* szCallBackURL);
struct SUBSCRIPTION* PushNewSubscription(char* szWebSocketId, char* sz_topic);
struct SUBSCRIPTION* AddInfoToSusbcription(char* szWebSocketId, char* szCallBackURL, char* sz_topic, char* sz_secret, char* sz_XAPIKey, char* sz_challenge, int lease_seconds, BOOL create_new_subsc);
BOOL DeleteSubscription(char* szWebSocketId, char* sz_topic);

struct NOTIFICATION* GetMemoryForNotificationsIfNeeded(struct SUBSCRIPTION* subs);
void FreeMemoryOfOneNotification(struct SUBSCRIPTION* subs, size_t i_notif);
void FreeMemoryAllNotifications(struct SUBSCRIPTION* subs);
BOOL AddNotificationsToSubscriptions(char* szWebSockedId, char* szWebCallbackURL, char* content_data);


struct WS_CONNECTION* GetMemoryWSConnectionIfNeeded(void)
{
    if (max_nWSConnections == 0)
    {        
        nWSConnections = 0;
        max_nWSConnections = INCR_WSCONNECTION;
        if (NULL == (WSConnections = (struct WS_CONNECTION*)calloc(max_nWSConnections, sizeof(*WSConnections))))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Not enought memory in line: " << __LINE__ << " file: " << __FILE__ << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            return NULL;
        }
    }
    else if (nWSConnections == max_nWSConnections)
    {
        struct WS_CONNECTION* p;
        max_nWSConnections += INCR_WSCONNECTION;        
        if (NULL == (p = (struct WS_CONNECTION*)recalloc(WSConnections, max_nWSConnections * sizeof(*WSConnections), nWSConnections * sizeof(*WSConnections))))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Not enought memory in line: " << __LINE__ << " file: " << __FILE__ << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            return NULL;
        }        
        WSConnections = p;
    }
    return WSConnections;
}

void FreeMemoryOfOneWSConnection(size_t i_connec)
{

    if (i_connec < nWSConnections && WSConnections)
    {
        if (WSConnections[i_connec].szWebSocketId) {
            free(WSConnections[i_connec].szWebSocketId);
            WSConnections[i_connec].szWebSocketId = NULL;
        }
        FreeMemoryAllSubscriptions(&WSConnections[i_connec]);
    }
}

void FreeMemoryAllWSConnections(void)
{
    if (WSConnections)
    {
        for (size_t i_connec = 0; i_connec < nWSConnections; i_connec++)
            FreeMemoryOfOneWSConnection(i_connec);
        nWSConnections = 0;
        max_nWSConnections = 0;
        free(WSConnections);
        WSConnections = NULL;
    }
}

struct WS_CONNECTION* GetWSConnection(char* szWebSocketId)
{
    size_t i_connec;

    // Search the WS connection related to this subscription
    if (!WSConnections)
        return NULL;

    for (i_connec = 0; i_connec < nWSConnections; i_connec++)
    {
        if (0 == _stricmp(WSConnections[i_connec].szWebSocketId, szWebSocketId))
            break;
    }
    if (i_connec == nWSConnections)
        return NULL;
    return &WSConnections[i_connec];
}

size_t PushNewWSConnection(char* szScriptName)
{
size_t i_connec;
#ifdef DEBUG_TO_TEMP

#endif  //DEBUG_TO_TEMP    

    // Search that there are any Ws connection with the same identifier    
    if(NULL!=GetWSConnection(szScriptName))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "This WS Connection is already opened: " << szScriptName <<  std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return MAXSIZE_T;     
    }
    // Push a new one
    GetMemoryWSConnectionIfNeeded();
    i_connec = nWSConnections;
    
    WSConnections[i_connec].szWebSocketId = _strdup(szScriptName);
    nWSConnections++;
    return i_connec;
}

struct SUBSCRIPTION* GetMemoryForSubscriptionIfNeeded(struct WS_CONNECTION* ws)
{
    if (!ws)
        return NULL;
    if (ws->max_nSubscriptions == 0)
    {
        ws->nSubscriptions = 0;
        ws->max_nSubscriptions = INCR_SUBSCRIPTIONS;
        if (NULL == (ws->Subscriptions = (struct SUBSCRIPTION*)calloc(ws->max_nSubscriptions, sizeof(*ws->Subscriptions))))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Not enought memory in line: " << __LINE__ << " file: " << __FILE__ << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            return NULL;
        }
    }
    else if (ws->nSubscriptions == ws->max_nSubscriptions)
    {
        struct SUBSCRIPTION* p;
        ws->max_nSubscriptions += INCR_SUBSCRIPTIONS;
        if (NULL == (p = (struct SUBSCRIPTION*)recalloc(ws->Subscriptions, ws->max_nSubscriptions * sizeof(*ws->Subscriptions), ws->nSubscriptions * sizeof(*ws->Subscriptions))))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app);
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Not enought memory in line: " << __LINE__<<" file: "<<  __FILE__ << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            return NULL;
        }
        ws->Subscriptions = p;
    }
    return ws->Subscriptions;
}

void FreeMemoryOfOneSubscription(struct WS_CONNECTION* ws, size_t i_subs)
{
    
    if (ws && i_subs < ws->nSubscriptions && ws->Subscriptions)
    {
        if (ws->Subscriptions[i_subs].szCallBackURL) {
            free(ws->Subscriptions[i_subs].szCallBackURL);
            ws->Subscriptions[i_subs].szCallBackURL = NULL;
        }
        if (ws->Subscriptions[i_subs].szTopic) {
            free(ws->Subscriptions[i_subs].szTopic);
            ws->Subscriptions[i_subs].szTopic = NULL;
        }
        if (ws->Subscriptions[i_subs].szSecret) {
            free(ws->Subscriptions[i_subs].szSecret);
            ws->Subscriptions[i_subs].szSecret = NULL;
        }
        if (ws->Subscriptions[i_subs].szXAPIKey) {
            free(ws->Subscriptions[i_subs].szXAPIKey);
            ws->Subscriptions[i_subs].szXAPIKey = NULL;
        }
        if (ws->Subscriptions[i_subs].szChallenge) {
            free(ws->Subscriptions[i_subs].szChallenge);
            ws->Subscriptions[i_subs].szChallenge = NULL;
        }        
        FreeMemoryAllNotifications(&ws->Subscriptions[i_subs]);
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Vaig a parar el temps: " << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
#ifdef TIMER_SUBS
        std::this_thread::sleep_for(std::chrono::seconds(4));
        ws->0Subscriptions[i_subs].tm.stop();
#endif
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Temps aturat: " << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
    }
}

void FreeMemoryAllSubscriptions(struct WS_CONNECTION* ws)
{
    if (ws)
    {
        if (ws->Subscriptions)
        {
            for (size_t i_subs = 0; i_subs < ws->nSubscriptions; i_subs++)
                FreeMemoryOfOneSubscription(ws, i_subs);
            free(ws->Subscriptions);
            ws->Subscriptions = NULL;
        }
        ws->max_nSubscriptions = ws->nSubscriptions = 0;
    }    
}

size_t GetSubscriptionIndiceFromWSConnection(struct WS_CONNECTION* ws, char* szCallBackURL)
{
    if (!ws)
        return MAXSIZE_T;

    size_t i_subs;
    // Search that there are any subscription with the same identifier
    for (i_subs = 0; i_subs < ws->nSubscriptions; i_subs++)
    {
        if (0 == _stricmp(ws->Subscriptions[i_subs].szCallBackURL, szCallBackURL))
            break;
    }
    if (i_subs == ws->nSubscriptions)
        return MAXSIZE_T;

    return i_subs;

}

struct SUBSCRIPTION* GetSubscription(char* szWebSocketId, char* szCallBackURL)
{    
    struct WS_CONNECTION* ws;
    if (NULL == (ws = GetWSConnection(szWebSocketId)))
        return NULL;

    size_t i_subs= GetSubscriptionIndiceFromWSConnection(ws, szCallBackURL);
    if (i_subs == MAXSIZE_T)
        return NULL;
    return ws->Subscriptions + i_subs;
}

struct SUBSCRIPTION* PushNewSubscription(char* szWebSocketId, char* szCallBackURL)
{

    struct WS_CONNECTION* ws;
    if (NULL == (ws = GetWSConnection(szWebSocketId)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error GetWSConnection" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        return NULL;
    }
    size_t i_subs = GetSubscriptionIndiceFromWSConnection(ws, szCallBackURL);    
    if (i_subs!=MAXSIZE_T)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Subscription: " << szCallBackURL <<" already exists" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return ws->Subscriptions+i_subs;
    }
    // Push a new one    
    GetMemoryForSubscriptionIfNeeded(ws);
    i_subs = ws->nSubscriptions;
    ws->Subscriptions[i_subs].szCallBackURL = _strdup(szCallBackURL);
    ws->nSubscriptions++;
    return &ws->Subscriptions[i_subs];
}


struct SUBSCRIPTION* AddInfoToSusbcription(char* szWebSocketId, char* szCallBackURL, char* sz_topic, char* sz_secret, char* sz_XAPIKey, char* sz_challenge, int lease_seconds, BOOL create_new_subsc)
{
    struct SUBSCRIPTION* subs;

    subs = GetSubscription(szWebSocketId, szCallBackURL);

    if (!subs)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app);
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Subscription no trobada: " << szCallBackURL << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP 
    }
    if (!subs && create_new_subsc)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Subscription no trobada intento fer un push: " << szCallBackURL << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP    
        subs = PushNewSubscription(szWebSocketId, szCallBackURL);
    }

    if(!subs)
        return NULL;

    // Adding the information to subscription
    if (subs->szSecret)
    {
        free(subs->szSecret);
        subs->szSecret = NULL;
    }
    if (sz_secret)
        subs->szSecret = _strdup(sz_secret);

    if (sz_topic)
    {
        if (subs->szTopic)
            free(subs->szTopic);
        subs->szTopic = _strdup(sz_topic);
    }
    if (sz_XAPIKey)
    {
        if (subs->szXAPIKey)
            free(subs->szXAPIKey);
        subs->szXAPIKey = _strdup(sz_XAPIKey);
    }
    if (sz_challenge)
    {
        if (subs->szChallenge)
            free(subs->szChallenge);
        subs->szChallenge = _strdup(sz_challenge);
    }    
    if(lease_seconds < 1)
        lease_seconds = 300;
    subs->lease_seconds = lease_seconds;
#ifdef TIMER_SUBS
    subs->tm.start(std::chrono::seconds(lease_seconds), DeleteSubscription, szWebSocketId, szCallBackURL);
#endif
    return subs;
}

BOOL DeleteSubscription(char* szWebSocketId, char * szCallBackURL)
{
    struct WS_CONNECTION* ws = GetWSConnection(szWebSocketId);
    if (!ws)
        return FALSE;
    size_t i_subs;
    if(MAXSIZE_T ==(i_subs = GetSubscriptionIndiceFromWSConnection(ws, szCallBackURL)))
        return FALSE;
    
    FreeMemoryOfOneSubscription(ws, i_subs);

#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Subscription deleted: " << szCallBackURL << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP

    if (i_subs == ws->nSubscriptions - 1) // last element
    {
        ws->nSubscriptions--;
    }
    else
    {        
        memmove(ws->Subscriptions + i_subs, ws->Subscriptions + i_subs + 1, (ws->nSubscriptions - i_subs - 1) * sizeof(*ws->Subscriptions));
        ws->nSubscriptions--;
        memset(&ws->Subscriptions[ws->nSubscriptions], 0, sizeof(*ws->Subscriptions));
    }    
    return TRUE;
}

struct NOTIFICATION* GetMemoryForNotificationsIfNeeded(struct SUBSCRIPTION *subs)
{
    if (!subs)
        return NULL;

    if (subs->max_nNotificacions == 0)
    {
        subs->nNotifications = 0;
        subs->max_nNotificacions = INCR_NOTIFICACIONS;
        if (NULL == (subs->Notifications = (struct NOTIFICATION*)calloc(subs->max_nNotificacions, sizeof(*subs->Notifications))))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Not enought memory in line: " << __LINE__ << " file: " << __FILE__ << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            return NULL;
        }
    }
    else if (subs->nNotifications == subs->max_nNotificacions)
    {
        struct NOTIFICATION* p;
        subs->max_nNotificacions += INCR_NOTIFICACIONS;
        if (NULL == (p = (struct NOTIFICATION*)recalloc(subs->Notifications, subs->max_nNotificacions * sizeof(*subs->Notifications), subs->nNotifications * sizeof(*subs->Notifications))))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Not enought memory in line: " << __LINE__ << " file: " << __FILE__ << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            return NULL;
        }
        subs->Notifications = p;
    }
    return subs->Notifications;
}


void FreeMemoryOfOneNotification(struct SUBSCRIPTION* subs, size_t i_notif)
{
    if (subs && i_notif < subs->nNotifications && subs->Notifications)
    {
        if (subs->Notifications[i_notif].dataPost)
        {
            free(subs->Notifications[i_notif].dataPost);
            subs->Notifications[i_notif].dataPost = NULL;
        }
    }
}

void FreeMemoryAllNotifications(struct SUBSCRIPTION* subs)
{
    if (subs)
    {
        if(subs->Notifications)
        {
            for (size_t i_notif = 0; i_notif < subs->nNotifications; i_notif++)
                FreeMemoryOfOneNotification(subs, i_notif);
            free(subs->Notifications);
            subs->Notifications = NULL;
        }
        subs->max_nNotificacions = subs->nNotifications = 0;
    }    
}

BOOL AddNotificationsToSubscriptions(char * szWebSockedId, char* szWebCallbackURL, char *content_data)
{
    struct SUBSCRIPTION* subs;

    if(NULL==(subs=GetSubscription(szWebSockedId, szWebCallbackURL)))
        return FALSE;
    
    GetMemoryForNotificationsIfNeeded(subs);
    if (NULL == (subs->Notifications[subs->nNotifications].dataPost = _strdup(content_data)))
        return FALSE;
    subs->nNotifications++;
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Notification created\n"<< std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    return TRUE;
}



// GENERAL FUNCTIONS

// Searching a string "find" in string "s" in a insensible way
char *stristr(const char *s, const char *find)
{
    const char* c, * sc;
    size_t len;

    if (*(c = find++) != '\0')
    {
        len = strlen(find);
        do
        {
            do
            {
                if (*(sc = s++) == '\0')
                    return 0;
            } while (_strnicmp(sc, c, 1));
        } while (_strnicmp(s, find, len) != '\0');
        s--;
    }
    return (char*)s;
}


void* recalloc(void* block, size_t new_size, size_t old_size)
{
    void* p;
    if (NULL == (p = realloc(block, new_size)))
        return NULL;
    if (new_size > old_size)
        memset((char*)p + old_size, 0, new_size - old_size);
    return p;
}

BYTE* stringToHexa(char* str_text)
{
    size_t text_len = std::strlen(str_text);
    if (text_len < 1)
        return NULL;
    BYTE* str_hex = (BYTE*)malloc(text_len * 2 + 1); // 2 hex = 1 ASCII char + 1 for null char

    if (str_hex == NULL)
        return NULL;

    size_t i, hex_index = 0;
    for (i = 0; i < text_len; i++, hex_index += 2)
        std::sprintf((char*)(str_hex + hex_index), "%02X", str_text[i]);

    str_hex[text_len * 2] = '\0';
    return str_hex;
}

char* DeleteLastCharOfString(char* string, const char c)
{
    size_t l;
    l = strlen(string);
    if (l > 0 && string[l - 1] == c)
        string[l - 1] = '\0';
   
    return string;
}
char* strnzcpy(char* dest, const char* src, size_t maxlen)
{
    size_t i;
    if (!maxlen)
        i = 0;
    else
        strncpy(dest, src, i = maxlen - 1);

    dest[i] = '\0';
    return dest;
}

int CharToUnicode(LPCSTR lpMultiByteStr, LPWSTR lpWideCharStr, size_t cchWideChar)
{
    return MultiByteToWideChar(CP_OEMCP, 0, lpMultiByteStr, -1, lpWideCharStr, (int)cchWideChar);
}

int CharToUTF8(LPCSTR CharStr, LPSTR UTF8Str, size_t cchUTF8Str)
{
    LPWSTR wide_char_str;
    size_t cchWideChar;

    cchWideChar = strlen(CharStr) + 1;
    if (NULL == (wide_char_str = (LPWSTR)malloc(cchWideChar * 2)))
    {
        strnzcpy(UTF8Str, CharStr, cchUTF8Str);
        return (int)strlen(CharStr);
    }
    if (0 == CharToUnicode(CharStr, wide_char_str, cchWideChar))
    {
        free(wide_char_str);
        strnzcpy(UTF8Str, CharStr, cchUTF8Str);
        return (int)strlen(CharStr);
    }
    int return_value = WideCharToMultiByte(CP_UTF8, 0, wide_char_str, -1, UTF8Str, (int)cchUTF8Str, NULL, NULL);
    free(wide_char_str);
    return return_value;
}

BOOL ExpandAndCopyUTF8FromChar(LPSTR* UTF8Str, size_t* cchUTF8Str, const char* s)
{
    if (*cchUTF8Str < strlen(s) * 4 + 1)
    {
        *cchUTF8Str = strlen(s) * 4 + 1;
        void *p_temp;
        if (NULL == (p_temp = realloc(*UTF8Str, *cchUTF8Str)))
            return FALSE;
        *UTF8Str = (LPSTR)p_temp;
    }
    CharToUTF8(s, *UTF8Str, *cchUTF8Str);
    return TRUE;
}


// QUERY PARAMETERS functions
char* GetCallBackURL(const char* name_topic_key, char* query, char* sz_WebSocketId)
{
    char* szCallBackURL=NULL;
    char sztopic[MAX_LENGTH_TOPIC];
    if (NULL!=GetQueryParameter(sztopic, MAX_LENGTH_TOPIC, name_topic_key, query))
    {
        if(NULL==(szCallBackURL = (char*)malloc(strlen(sz_WebSocketId) + 1 + strlen(name_topic_key) + 1 + strlen(sztopic) + 1)))
            return NULL;
        if (NULL != strchr(sz_WebSocketId, '?'))
            sprintf(szCallBackURL, "%s&%s=%s", sz_WebSocketId, name_topic_key, sztopic);
        else
            sprintf(szCallBackURL, "%s?%s=%s", sz_WebSocketId, name_topic_key, sztopic);
    }
    else
        szCallBackURL = _strdup(sz_WebSocketId);
    return szCallBackURL;
}

// Give the value of the query parameter 'name'
char* GetQueryParameter(char* value, size_t value_size, const char* name, char* query)
{
size_t i_name=0, i_value = 0;
BOOL check_the_name = TRUE, have_name = FALSE, have_question_mark=FALSE;
int c2;
char mini_string[3];
char* p, * p_ini;

    if (!query || !name || !value)
        return NULL;

    mini_string[2] = '\0';        
    p_ini = query;
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Searching the key: " << name << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    for (p = query; *p; p++)
    {
        switch (*p)
        {
            case '=':
                /*end of name*/
                if (check_the_name)
                {
                    check_the_name = FALSE;
                    if (name[i_name] == '\0')                        
                        have_name = TRUE;
                    c2 = '\0';
                }
                else
                    c2 = '=';  //This is a '=' inside the parameter value that must be respected.
                /*i_name++;*/
                break;
            case '?':
                if (have_question_mark)
                {
                    c2 = *p;
                    break;
                }
                else
                    have_question_mark = TRUE;
                // I don't break explicitly, '&' and '?' they are treated the same except for this bit of code
                // They differ in that only the first question mark should be treated as a separator            
            case '&':
                /*end of value*/
                if (!have_question_mark)
                {
                    // There is an error in the query if there is a & without ?
                    return NULL;
                }
                if (have_name)
                {
                    value[i_value] = '\0';
#ifdef DEBUG_TO_TEMP
                    outputFile.open(szDebugFile, std::ofstream::app); 
                    if (outputFile.is_open()) { // check if the file was opened successfully
                        outputFile << "Value found: " << value << std::endl; // write data to the file
                        outputFile.close(); // close the file when done
                    }
#endif  //DEBUG_TO_TEMP
                    return value;
                }
                check_the_name = TRUE;
                i_name = 0;
                c2 = '\0';
                break;
            case '+':
                /*Space*/
                c2 = ' ';
                break;
            case '%':
                /*Special character*/
                p++;
                if (!*p || !*(p + 1))
                {
                    /*Format error*/
                    return NULL;
                }
                mini_string[0] = *p;
                p++;
                mini_string[1] = *p;
                #ifdef _MSC_VER
                #pragma warning( disable : 6031)
                #endif
                sscanf(mini_string, "%x", &c2);
                #ifdef _MSC_VER
                #pragma warning( default : 6031)
                #endif
                if (c2 == '\r')
                    c2 = '\0';
                /*else if (c2=='\n')
                {
                    c2='\n';
                } */
                break;
            default:
                c2 = *p;
        }
        if (c2 == '\0')
            continue;
        if (check_the_name)
        {
           if (toupper(name[i_name++]) != toupper(c2))
               check_the_name = FALSE;
            
        }
        else if (have_name)
        {
            if (i_value + 1 < value_size) 
                value[i_value++] = (char)c2;
        }
    }    
    if (have_name)
    {
        value[i_value] = '\0';
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Value found: " << value << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return value;
    }
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Value not found" << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    return NULL;
}



// HASH Functions

#define HASH_ALG_ID_SHA_1       0
#define HASH_ALG_ID_SHA_256     1
#define HASH_ALG_ID_SHA_384     2
#define HASH_ALG_ID_SHA_512     3

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL  
    #define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#endif

PBYTE CreateHMACHash2(BYTE hashAlg, char* szSecret, char* szMessage)
{
BCRYPT_ALG_HANDLE       hAlg = NULL;
BCRYPT_HASH_HANDLE      hHash = NULL;
NTSTATUS                status = STATUS_UNSUCCESSFUL;
DWORD                   cbData = 0,
    cbHash = 0,
    cbHashObject = 0;
PBYTE                   pbHashObject = NULL;
PBYTE                   pbHash = NULL;
//CONST BYTE key[] = { "SecretKey" };
//CONST BYTE message[] = { "<SomeXmlData />" };

BYTE* HexSecret = NULL;
BYTE* HexMessage = NULL;


    if (!szSecret || !szMessage)
    {
    #ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "secret and message" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
    #endif  //DEBUG_TO_TEMP
        return NULL;
    }
    if (NULL == (HexSecret = stringToHexa(szSecret)))
    {
    #ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error converting secret to hex" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
    #endif  //DEBUG_TO_TEMP
        return NULL;
    }
    if (NULL == (HexMessage = stringToHexa(szMessage)))
    {
    #ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error converting message to hex" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
    #endif  //DEBUG_TO_TEMP
        if (HexSecret) free(HexSecret);
        return NULL;
    }

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error "<< status << " returned by BCryptOpenAlgorithmProvide" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return NULL;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error " << status << " returned by BCryptGetProperty BCRYPT_OBJECT_LENGTH" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        
        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Not enough memory for pbHashObject" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        

        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        if (hHash)
            BCryptDestroyHash(hHash);
        if (pbHashObject)
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        return NULL;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error " << status << " returned by BCryptGetProperty BCRYPT_HASH_LENGTH" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        

        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        if (hHash)
            BCryptDestroyHash(hHash);
        if (pbHashObject)
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        return NULL;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Not enough memory for pbHash" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        

        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        if (hHash)
            BCryptDestroyHash(hHash);
        if (pbHashObject)
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        return NULL;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        (PBYTE)HexSecret,
        sizeof(HexSecret),
        0)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error " << status << " returned by BCryptCreateHash" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        

        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        if (hHash)
            BCryptDestroyHash(hHash);
        if (pbHashObject)
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        return NULL;
    }

    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(
        hHash,
        (PBYTE)HexSecret,
        sizeof(HexSecret),
        0)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error " << status << " returned by BCryptHashData" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP 
        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        if (hHash)
            BCryptDestroyHash(hHash);
        if (pbHashObject)
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        return NULL;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error " << status << " returned by BCryptFinishHash" << std::endl; // write data to the file            
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP 
        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        if (hHash)
            BCryptDestroyHash(hHash);
        if (pbHashObject)
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        return NULL;
    }

    /*printf("The hash is:  ");
    for (DWORD i = 0; i < cbHash; i++)
    {
        printf("%2.2X-", pbHash[i]);
    }*/
#ifdef DEBUG_TO_TEMP
    if (outputFile.is_open()) { // check if the file was opened successfully        

        char str[100];
        sprintf(str, "The hash is:  ");
        for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf(str, "%2.2x ", pbHash[i]);
        }
        printf("\n");
        outputFile << "hash value: " << pbHash << "\nhash sense w: \n" << str << std::endl; // write data to the file            
        outputFile.close(); // close the file when done

    }
#endif  //DEBUG_TO_TEMP 
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)
        BCryptDestroyHash(hHash);
    if (pbHashObject)
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    return pbHash;
}

PBYTE CreateHMACHash(BYTE hashAlg, char* szSecret, char* szMessage)
{
    /*A hashed message authentication checksum(HMAC) is typically used to verify that a message has not been changed during transit.
    Both parties to the message must have a shared secret key.The sender combines the keyand the message into a string, creates a digest of the string by using an algorithm
    such as SHA - 1 or MD5, and transmits the messageand the digest.The receiver combines the shared key with the message, applies the appropriate algorithm,
    and compares the digest thus obtained with that transmitted by the sender.If the digests are exactly the same, the message was not tampered with.*/

    //--------------------------------------------------------------------
    // Declare variables.
    //
    // hProv:           Handle to a cryptographic service provider (CSP). 
    //                  This example retrieves the default provider for  
    //                  the PROV_RSA_FULL provider type.  
    // hHash:           Handle to the hash object needed to create a hash.
    // hKey:            Handle to a symmetric key. This example creates a 
    //                  key for the RC4 algorithm.
    // hHmacHash:       Handle to an HMAC hash.
    // pbHash:          Pointer to the hash.
    // dwDataLen:       Length, in bytes, of the hash.
    // secret:           Password string used to create a symmetric key.
    // message:           Message string to be hashed.
    // HmacInfo:        Instance of an HMAC_INFO structure that contains 
    //                  information about the HMAC hash.
    // 
    HCRYPTPROV  hProv = NULL;
    HCRYPTHASH  hHash = NULL;
    HCRYPTKEY   hKey = NULL;
    HCRYPTHASH  hHmacHash = NULL;
    PBYTE       pbHash = NULL;
    DWORD       dwDataLen = 0;
    BYTE* HexSecret = NULL;
    BYTE* HexMessage = NULL;

    HMAC_INFO   HmacInfo;
    ALG_ID HashAlgid;

    if (!szSecret || !szMessage)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "secret and message" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return NULL;
    }
    // Converts the secret and the message to hexadecimal 

    if (NULL == (HexSecret = stringToHexa(szSecret)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error converting secret to hex" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return NULL;
    }
    if (NULL == (HexMessage = stringToHexa(szMessage)))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error converting message to hex" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (HexSecret) free(HexSecret);
        return NULL;
    }
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "HEX Secret: " << HexSecret << "HEX Message: " << HexMessage << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP

    //--------------------------------------------------------------------
    // Zero the HMAC_INFO structure and use the hash_alg algorithm for
    // hashing.

    ZeroMemory(&HmacInfo, sizeof(HmacInfo));

    if (hashAlg == HASH_ALG_ID_SHA_1)
        HashAlgid = CALG_SHA1;
    else if (hashAlg == HASH_ALG_ID_SHA_256)
        HashAlgid = CALG_SHA_256;
    else if (hashAlg == HASH_ALG_ID_SHA_384)
        HashAlgid = CALG_SHA_384;
    else if (hashAlg == HASH_ALG_ID_SHA_512)
        HashAlgid = HASH_ALG_ID_SHA_512;
    else
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "HASH algorithm unknowned" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }
    HmacInfo.HashAlgid = HashAlgid;

    //--------------------------------------------------------------------
    // Acquire a handle to the default RSA cryptographic service provider.
    // https://stackoverflow.com/questions/4191312/windows-cryptoapi-cryptsignhash-with-calg-sha-256-and-private-key-from-my-keyst
    if (!CryptAcquireContext(
        &hProv,                   // handle of the CSP
        NULL,                     // key container name
        MS_ENH_RSA_AES_PROV,     // CSP name
        PROV_RSA_AES,            // provider type
        0))     // no key access is requested
    
    /*if (!CryptAcquireContext(
        &hProv,                   // handle of the CSP
        NULL,                     // key container name
        NULL,                     // CSP name
        PROV_RSA_FULL,            // provider type
        CRYPT_VERIFYCONTEXT))     // no key access is requested*/
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in AcquireContext 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    //--------------------------------------------------------------------
    // Derive a symmetric key from a hash object by performing the
    // following steps:
    //    1. Call CryptCreateHash to retrieve a handle to a hash object.
    //    2. Call CryptHashData to add a text string (password) to the 
    //       hash object.
    //    3. Call CryptDeriveKey to create the symmetric key from the
    //       hashed password derived in step 2.
    // You will use the key later to create an HMAC hash object. 

    if (!CryptCreateHash(
        hProv,                    // handle of the CSP
        HashAlgid,                // hash algorithm to use
        0,                        // hash key
        0,                        // reserved
        &hHash))                  // address of hash object handle
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[1000], str2[512];
            WCHAR wstr2[512];
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), LANG_SYSTEM_DEFAULT, wstr2, 512, NULL);
            wcstombs(str2, wstr2, wcslen(wstr2));
            str2[wcslen(wstr2)] = '\0';
            sprintf(str, "Error in CryptCreateHash 0x%08x %s\n", GetLastError(), str2);
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    if (!CryptHashData(
        hHash,                    // handle of the hash object
        HexSecret,                    // password to hash
        sizeof(HexSecret),            // number of bytes of data to add
        0))                       // flags
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptHashData 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    if (!CryptDeriveKey(
        hProv,                    // handle of the CSP
        CALG_RC4,                 // algorithm ID
        hHash,                    // handle to the hash object
        0,                        // flags
        &hKey))                   // address of the key handle
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptDeriveKey 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    //--------------------------------------------------------------------
    // Create an HMAC by performing the following steps:
    //    1. Call CryptCreateHash to create a hash object and retrieve 
    //       a handle to it.
    //    2. Call CryptSetHashParam to set the instance of the HMAC_INFO 
    //       structure into the hash object.
    //    3. Call CryptHashData to compute a hash of the message.
    //    4. Call CryptGetHashParam to retrieve the size, in bytes, of
    //       the hash.
    //    5. Call malloc to allocate memory for the hash.
    //    6. Call CryptGetHashParam again to retrieve the HMAC hash.

    if (!CryptCreateHash(
        hProv,                    // handle of the CSP.
        CALG_HMAC,                // HMAC hash algorithm ID
        hKey,                     // key for the hash (see above)
        0,                        // reserved
        &hHmacHash))              // address of the hash handle
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptCreateHash 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHmacHash)
            CryptDestroyHash(hHmacHash);
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    if (!CryptSetHashParam(
        hHmacHash,                // handle of the HMAC hash object
        HP_HMAC_INFO,             // setting an HMAC_INFO object
        (BYTE*)&HmacInfo,         // the HMAC_INFO object
        0))                       // reserved
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptSetHashParam 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHmacHash)
            CryptDestroyHash(hHmacHash);
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    if (!CryptHashData(
        hHmacHash,                // handle of the HMAC hash object
        HexMessage,                    // message to hash
        sizeof(HexMessage),            // number of bytes of data to add
        0))                       // flags
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptHashData 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHmacHash)
            CryptDestroyHash(hHmacHash);
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    //--------------------------------------------------------------------
    // Call CryptGetHashParam twice. Call it the first time to retrieve
    // the size, in bytes, of the hash. Allocate memory. Then call 
    // CryptGetHashParam again to retrieve the hash value.

    if (!CryptGetHashParam(
        hHmacHash,                // handle of the HMAC hash object
        HP_HASHVAL,               // query on the hash value
        NULL,                     // filled on second call
        &dwDataLen,               // length, in bytes, of the hash
        0))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptGetHashParam 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHmacHash)
            CryptDestroyHash(hHmacHash);
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    pbHash = (BYTE*)malloc(dwDataLen);
    if (NULL == pbHash)
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Unable to allocate memory \n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHmacHash)
            CryptDestroyHash(hHmacHash);
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }

    if (!CryptGetHashParam(
        hHmacHash,                 // handle of the HMAC hash object
        HP_HASHVAL,                // query on the hash value
        pbHash,                    // pointer to the HMAC hash value
        &dwDataLen,                // length, in bytes, of the hash
        0))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[200];
            sprintf(str, "Error in CryptGetHashParam 0x%08x \n", GetLastError());
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (hHmacHash)
            CryptDestroyHash(hHmacHash);
        if (hKey)
            CryptDestroyKey(hKey);
        if (hHash)
            CryptDestroyHash(hHash);
        if (hProv)
            CryptReleaseContext(hProv, 0);
        if (HexMessage) free(HexMessage);
        if (HexSecret) free(HexSecret);
        return pbHash;
    }    
    
    
#ifdef DEBUG_TO_TEMP
    // Print the hash to the console.
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        char str[500];
        sprintf(str, "The hash is:  ");
        for (DWORD i = 0; i < dwDataLen; i++)
        {
            sprintf(str, "%2.2x ", pbHash[i]);
        }
        printf("\n");
        outputFile << str << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP


    // Free resources.
    if (hHmacHash)
        CryptDestroyHash(hHmacHash);
    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    if (HexMessage) free(HexMessage);
    if (HexSecret) free(HexSecret);

    return pbHash;
}

// **********************************************
// SPECIFIC FUNCTIONS FOR RESPONSE THE REQUEST
// **********************************************

//  Global server instance
// IHtpServer * g_pHttpServer = NULL;

//  Global module context id
//PVOID g_pModuleContext = NULL;

/* Get current date/time, format is YYYY-MM-DD.HH:mm:ss
const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime_s(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    return buf;
}*/

HRESULT SendTextMessageToWebHub(IHttpResponse* pHttpResponse, const char* sztext, DWORD* pcbSent)
{
    BOOL CompletionExpected;
    DWORD cbSent = 0;

    if (sztext)
    {
        HTTP_DATA_CHUNK dataChunk[1];
        LPSTR UTF8Str = NULL;
        size_t cchUTF8Str = 0;

        if (!ExpandAndCopyUTF8FromChar(&UTF8Str, &cchUTF8Str, sztext) || !UTF8Str)
            return S_FALSE;

        // Set the chunk to a chunk in memory.
        dataChunk[0].DataChunkType = HttpDataChunkFromMemory;
        // Set the chunk to the first buffer.
        dataChunk[0].FromMemory.pBuffer = (PVOID)UTF8Str;
        // Set the chunk size to the first buffer size.
        dataChunk[0].FromMemory.BufferLength = (USHORT)strlen(UTF8Str);

        // Insert the data chunks into the response.
        if (pcbSent)
            *pcbSent = cbSent;
        HRESULT hr = pHttpResponse->WriteEntityChunks(dataChunk, 1, FALSE, FALSE, &cbSent, &CompletionExpected);

        if (FAILED(hr))
        {
            if (UTF8Str)
                free(UTF8Str);
            return hr;
        }
        if (UTF8Str)
            free(UTF8Str);
    }
    return pHttpResponse->Flush(false, true, &cbSent, &CompletionExpected);
}

#define FIRST_BYTE_FIN                    0x80  //the last message in a series. If it's 0, then the server keeps listening for more parts of the message; otherwise, the server should consider the message delivered
#define FIRST_BYTE_OPCODE                 0x0F  //11110000
#define FIRST_BYTE_OPCODE_TEXT               1  //00000001
#define FIRST_BYTE_OPCODE_BINARY             2  //00000010
//#define FIRST_BYTE_OPCODE_RESERVED3        3  //00000011
//#define FIRST_BYTE_OPCODE_RESERVED4        4  //00000100
//#define FIRST_BYTE_OPCODE_RESERVED5        5  //00000101
//#define FIRST_BYTE_OPCODE_RESERVED6        6  //00000110
//#define FIRST_BYTE_OPCODE_RESERVED7        7  //00000111
#define FIRST_BYTE_OPCODE_CLOSECONNECTION    8  //00001000
#define FIRST_BYTE_OPCODE_PING               9  //00001001
#define FIRST_BYTE_OPCODE_PONG              10  //00001010
//#define FIRST_BYTE_OPCODE_RESERVED11      11  //00001011
//#define FIRST_BYTE_OPCODE_RESERVED12      12  //00001100
//#define FIRST_BYTE_OPCODE_RESERVED13      13  //00001101
//#define FIRST_BYTE_OPCODE_RESERVED14      14  //00001110
//#define FIRST_BYTE_OPCODE_RESERVED15      15  //00001111
#define SECOND_BYTE_MASK                  0x80

HRESULT SendTextMessageToWebSocketClient(IHttpResponse *pHttpResponse, const char *sztext, DWORD *pcbSent)
{
    HRESULT hr; 
    HTTP_DATA_CHUNK dataChunk[1];
    BOOL CompletionExpected;
    DWORD cbSent;
    BYTE *buffer;  //This is NOT ended with /0.

    size_t len = strlen(sztext);
    if (NULL==(buffer = (BYTE *)malloc(len+10)))   //Mark is not considered in this code
        return -1;

    buffer[0] = FIRST_BYTE_FIN | FIRST_BYTE_OPCODE_TEXT;
    if (len < 126) {
        #ifdef _MSC_VER
        #pragma warning( disable : 6386 )
        #endif
        buffer[1] = (BYTE)len; // NJ: Diu això "Warning	C6386 Buffer overrun while writing to 'buffer':  the writable size is 'len+12' bytes, but '2' bytes might be written."
        // Pèrquè len és un size_t i en pot valer un numero que necessita dos BYTES però ja hem comprovat que no és així amb la condició anterior 
        // i per tant desactivo el warning
        #ifdef _MSC_VER
        #pragma warning( default : 6386 )
        #endif    
        memcpy(buffer + 2, sztext, len);
        // Set the chunk size to the first buffer size.
        dataChunk[0].FromMemory.BufferLength = (ULONG)(len + 2);
    }
    else if (len > 126 && len < 65536) {
        buffer[1] = (BYTE)126;
        buffer[2] = (BYTE)((len >> 8) & 0xFF);
        buffer[3] = (BYTE)(len & 0xFF);
        memcpy(buffer + 4, sztext, len);
        dataChunk[0].FromMemory.BufferLength = (ULONG)(len + 4);
    }
    else {
        #ifdef _MSC_VER
        #pragma warning( disable : 6386 )
        #endif
        buffer[1] = 127;
        #ifdef _MSC_VER
        #pragma warning( default : 6386 )
        #endif

        buffer[2] = (BYTE)((len >> 56) & 0x7F);
        buffer[3] = (BYTE)((len >> 48) & 0xFF);

        buffer[4] = (BYTE)((len >> 40) & 0xFF);
        buffer[5] = (BYTE)((len >> 32) & 0xFF);
        buffer[6] = (BYTE)((len >> 24) & 0xFF);
        buffer[7] = (BYTE)((len >> 16) & 0xFF);

        buffer[8] = (BYTE)((len>>8) & 0xFF);
        buffer[9] = (BYTE)(len & 0xFF);
        memcpy(buffer + 10, sztext, len);
        dataChunk[0].FromMemory.BufferLength = (ULONG)(len + 10);
    }

    // Set the chunk to a chunk in memory.
    dataChunk[0].DataChunkType = HttpDataChunkFromMemory;
    // Set the chunk to the first buffer.
    dataChunk[0].FromMemory.pBuffer = (PVOID)buffer;

    // Insert the data chunks into the response.
    hr = pHttpResponse->WriteEntityChunks(dataChunk, 1, false, true, &cbSent, &CompletionExpected);
    free(buffer);

    if (FAILED(hr))
        return hr;

    if (pcbSent)
        *pcbSent = cbSent;

    hr = pHttpResponse->Flush(false, true, &cbSent, &CompletionExpected);
    return hr;
}

HRESULT SendFlagMessageToWebSocketClient(IHttpResponse* pHttpResponse, BYTE flag) 
{
    HRESULT hr;
    HTTP_DATA_CHUNK dataChunk[1];
    BOOL CompletionExpected;
    DWORD cbSent;
    BYTE buffer[2];  //This is NOT ended with /0.

    buffer[0] = FIRST_BYTE_FIN | flag;
    buffer[1] = 0;

    // Set the chunk to a chunk in memory.
    dataChunk[0].DataChunkType = HttpDataChunkFromMemory;
    // Set the chunk to the first buffer.
    dataChunk[0].FromMemory.pBuffer = (PVOID)buffer;
    dataChunk[0].FromMemory.BufferLength = 2;

    // Insert the data chunks into the response.
    hr = pHttpResponse->WriteEntityChunks(dataChunk, 1, false, true, &cbSent, &CompletionExpected);

    if (FAILED(hr))
        return hr;

    hr = pHttpResponse->Flush(false, true, &cbSent, &CompletionExpected);
    return hr;
}

#define WEB_SOCKET_MESSAGE_TEXT                    0
#define WEB_SOCKET_MESSAGE_BINARY                  1
#define WEB_SOCKET_MESSAGE_CONTINUATION            2
#define WEB_SOCKET_MESSAGE_CLOSECONNECTION         3
#define WEB_SOCKET_MESSAGE_PING                    4
#define WEB_SOCKET_MESSAGE_PONG                    5
#define WEB_SOCKET_MESSAGE_ERROR                   6
#define WEB_SOCKET_MESSAGE_INPUT_BUFFER_TOO_SHORT  7  // Buffer allocatted for ReadEntityBody too short. A fragment of the message is returned anyway
#define WEB_SOCKET_MESSAGE_OUTPUT_BUFFER_TOO_SHORT 8  // Buffer allocatted for ExtractTextMessageFromWebSocketData too short. A sizeMessage==cbSent should work. A fragment of the message is returned anyway
int ExtractTextMessageFromWebSocketData(BYTE *buffer, DWORD cbSent, char *szMessage, size_t sizeMessage) 
{
    size_t len, offset_data;
    BOOL masked=FALSE;
    BYTE mask[4];

    if (cbSent < 1) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_ERROR;
    }

    if (!(buffer[0] & FIRST_BYTE_FIN)) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_CONTINUATION;
    }

    if ((buffer[0] & FIRST_BYTE_OPCODE) == FIRST_BYTE_OPCODE_CLOSECONNECTION) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_CLOSECONNECTION;
    }
    if ((buffer[0] & FIRST_BYTE_OPCODE) == FIRST_BYTE_OPCODE_PING) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_PING;
    }
    if ((buffer[0] & FIRST_BYTE_OPCODE) == FIRST_BYTE_OPCODE_PONG) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_PONG;
    }
    if ((buffer[0] & FIRST_BYTE_OPCODE) == FIRST_BYTE_OPCODE_BINARY) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_BINARY;
    }

    //Get the message size
    if (cbSent < 2) {
        szMessage[0] = '\0';
        return WEB_SOCKET_MESSAGE_ERROR;
    }    
    
    if ((buffer[1] & ~SECOND_BYTE_MASK) < 125) {
        len = buffer[1] & ~SECOND_BYTE_MASK;
        offset_data = 2;
    }
    else if ((buffer[1] & ~SECOND_BYTE_MASK) == 126) {
        if (cbSent < 4) {
            szMessage[0] = '\0';
            return WEB_SOCKET_MESSAGE_ERROR;
        }
        len = ((size_t)buffer[2] << 8) + buffer[3];
        offset_data = 4;
    }
    else { /*if (buffer[1] & ~SECOND_BYTE_MASK == 127)*/
        if (cbSent < 10) {
            szMessage[0] = '\0';
            return WEB_SOCKET_MESSAGE_ERROR;
        }
        len=((size_t)(buffer[2])<<56) + ((size_t)(buffer[3])<<48) + ((size_t)(buffer[4]) << 40) + ((size_t)(buffer[5])<<32) + 
            ((size_t)(buffer[6])<<24) + ((size_t)(buffer[7])<<16) + ((size_t)(buffer[8]) << 8) + buffer[9];
        offset_data = 10;
    }

    int retorn = WEB_SOCKET_MESSAGE_TEXT;
    //Get the message
    if (buffer[1] & SECOND_BYTE_MASK) {
        masked = true;
        if (cbSent < offset_data + 4) {
            retorn = WEB_SOCKET_MESSAGE_ERROR;
        }
        if (cbSent < offset_data + 4 + len) {
            len= cbSent - offset_data - 4;
            retorn=WEB_SOCKET_MESSAGE_INPUT_BUFFER_TOO_SHORT;
        }
        memcpy(mask, buffer + offset_data, 4);
        offset_data += 4;
    }
    else {
        if (cbSent < offset_data + len) {
            len = cbSent - offset_data;
            retorn = WEB_SOCKET_MESSAGE_INPUT_BUFFER_TOO_SHORT;
        }
    }

    len = min(len, sizeMessage - 1);  // Just in case the szMessage is too short
    
    if (len > sizeMessage - 1) {
        retorn = WEB_SOCKET_MESSAGE_OUTPUT_BUFFER_TOO_SHORT;
        len = sizeMessage - 1;
    }
    else
        retorn = WEB_SOCKET_MESSAGE_TEXT;

    memcpy(szMessage, buffer + offset_data, len);
    szMessage[len] = '\0';

    if (masked) {
        //Unmask the message
        for (size_t i = 0; i < len; i++)
            szMessage[i] = szMessage[i] ^ mask[i % 4];
    }
    return retorn;
}

BOOL ProcessRequestToWebSocketClient(IHttpResponse* pHttpResponse, void* buffer, DWORD cbSent)
{
HRESULT hr;
    char* szMessage = (char*)malloc(cbSent);
    int retorn = ExtractTextMessageFromWebSocketData((BYTE *)buffer, cbSent, szMessage, cbSent);

#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Extract text response: " << retorn << "\n" << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP

    if (retorn == WEB_SOCKET_MESSAGE_CLOSECONNECTION) {
        //Send a response telling that we will to close
        //Send a pong
        hr = SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Connection Closed\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        return TRUE;
    }
    if (retorn == WEB_SOCKET_MESSAGE_PING) {
        //Send a pong
        hr = SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_PONG);

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Pong\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

    }
    else if (retorn == WEB_SOCKET_MESSAGE_PONG)
        ; //Verify if this was a result of our ping (not implemented yet)
    else if (retorn == WEB_SOCKET_MESSAGE_BINARY)
        ; //Not implemented
    else if (retorn == WEB_SOCKET_MESSAGE_CONTINUATION) {
        ; //Not implemented
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Message continuation not implemented\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
    }
    else if (retorn == WEB_SOCKET_MESSAGE_ERROR) {
        ;
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Error interpreting the incoming message\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
    }
    else {
        hr = SendTextMessageToWebSocketClient(pHttpResponse, szMessage, &cbSent);
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "HRESULT Echo success?: " << SUCCEEDED(hr) << " cdSent " << cbSent << ":" << szMessage << "\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        if (FAILED(hr))
        {
            // Set the HTTP status.
            SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);
            return TRUE;
        }
    }
    return FALSE;
}// Fi de ProcessRequestToWebSocketClient()


BOOL ProcessPostRequestFromServer(IN IHttpContext* pHttpContext, IHttpResponse* pHttpResponse, IHttpRequest *pHttpRequest, PSTR szRequest, char *szWebSockedId)
{
    char* sig_value = NULL;
    PCSTR pcstr = NULL;

    EnterCriticalSection(&SubscriptionsSection);
    char *szCallBackURL=GetCallBackURL(szTopic_Param, szRequest, szWebSockedId);
    if (!szCallBackURL)
    {
        LeaveCriticalSection(&SubscriptionsSection);
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "Subscription not found", NULL);
        return FALSE;
    }
    struct SUBSCRIPTION* subs = GetSubscription(szWebSockedId, szCallBackURL);
    if(!subs)
    {
        LeaveCriticalSection(&SubscriptionsSection);
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "Subscription not found", NULL);
        free(szCallBackURL);
        return FALSE;
    }
#ifdef DE_MOMENT_NO_HO_USEM
    char sz_XAPIKey[MAX_LENGTH_XAPIKEY];
    *sz_XAPIKey = '\0';    
    GetQueryParameter(sz_XAPIKey, MAX_LENGTH_XAPIKEY, szXAPIKey_Param, szRequest);
    if (subs->szXAPIKey && 0 != _stricmp(subs->szXAPIKey, sz_XAPIKey))
    {        
        LeaveCriticalSection(&SubscriptionsSection);
        char str[50];
        sprintf(str, "%s incorrect or missing", szXAPIKey_Param);
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, str, NULL);
        free(szCallBackURL);
        return FALSE;
    }    
#endif

    // Checking the header "X-Hub-Signature"
    if (subs->szSecret) // Secret is optional
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Secret: " << subs->szSecret << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        
        char *szXHubSignature = NULL;
        USHORT cchXHubSignature = 0;

        pHttpRequest->GetHeader("X-Hub-Signature", &cchXHubSignature);
        if (cchXHubSignature > 0) // The header length will be 0 if the header was not found.
        {
            if (NULL == (pcstr = pHttpRequest->GetHeader("X-Hub-Signature", &cchXHubSignature)))
            {
                LeaveCriticalSection(&SubscriptionsSection);
               pHttpResponse->SetStatus(507, "", 0, 0);
#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "'X-Hub-Signature' is missing" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP
                SendTextMessageToWebHub(pHttpResponse, "Not enough memory", NULL);
                free(szCallBackURL);
                return FALSE;
            }
            if (NULL == (szXHubSignature = (char*)malloc(((size_t)cchXHubSignature + 1) * sizeof(char*))))
            {
                LeaveCriticalSection(&SubscriptionsSection);
                pHttpResponse->SetStatus(507, "", 0, HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY));
                SendTextMessageToWebHub(pHttpResponse, "Not enough memory", NULL);
                free(szCallBackURL);
                return FALSE;
            }
            strcpy(szXHubSignature, pcstr);
        }
        else
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(204, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, NULL, NULL);
            free(szCallBackURL);
            return FALSE;
        }
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "X-Hub-Signature: " << szXHubSignature << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        // Getting the algorithm of the hash
        char* p = strchr(szXHubSignature, '=');
        if (p == NULL)
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(204, "", 0, 0);
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "'X-Hub-Signature' has wrong format" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            free(szCallBackURL);
            free(szXHubSignature);
            SendTextMessageToWebHub(pHttpResponse, NULL, NULL);
            return FALSE;
        }
        char* alg;
        size_t len = (ptrdiff_t)p - (ptrdiff_t)szXHubSignature;
        if (NULL == (alg = (char*)malloc(len + 1)))
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(507, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Not enough memory", NULL);
            free(szCallBackURL);
            free(szXHubSignature);
            return FALSE;
        }
        memcpy(alg, szXHubSignature, len);
        alg[len] = '\0';

        // For the moment we only supports SHA256
        if (0 != _stricmp(alg, "sha256"))
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(404, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Hash Algorithm doesn't supported", NULL);
            free(szCallBackURL);
            free(szXHubSignature);
            free(alg);
            return FALSE;
        }
        /*
        BYTE hashAlgId;
        if (0 == _stricmp(alg, "sha1"))
            hashAlgId = HASH_ALG_ID_SHA_1;
        else if(0 == _stricmp(alg, "sha256"))
            hashAlgId = HASH_ALG_ID_SHA_256;
        else if (0 == _stricmp(alg, "sha384"))
            hashAlgId = HASH_ALG_ID_SHA_384;
        else if (0 == _stricmp(alg, "sha512"))
            hashAlgId = HASH_ALG_ID_SHA_512;
        else
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(404, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Hash Algorithm doesn't supported", NULL);
            free(szCallBackURL);
            return FALSE;
        }
        */
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app);
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "algorithm: " << alg << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        free(alg);

        // Getting the message in hexadecimal
        len = strlen(p + 1);
        if (NULL == (sig_value = (char*)malloc(len + 1)))
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(507, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Not enough memory", NULL);
            free(szCallBackURL);
            free(szXHubSignature);
            return FALSE;
        }
        memcpy(sig_value, p + 1, len);
        sig_value[len] = '\0';
        //strcpy(sig_value, p + 1);

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << " value of signature: " << sig_value << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        free(szXHubSignature);
    }
#ifdef DEBUG_TO_TEMP
    else
    { 
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "No Secret" << std::endl; // write data to the fil
            outputFile.close(); // close the file when done
        }
    }
#endif  //DEBUG_TO_TEMP
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app);
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "linia "<< __LINE__ << "\n" << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    // Getting the content of the request
    char *szrequest_body=NULL;
    DWORD cbSent, request_size = 100024;

    //request_size=pHttpRequest->GetRemainingEntityBytes();

#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app);
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "request_size: " << request_size << "\n" << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    if (request_size > 0)
    {
        if (NULL == (szrequest_body = (char*)pHttpContext->AllocateRequestMemory(request_size + 1)))
        {
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app);
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "linia " << __LINE__ << " pHttpContext->AllocateRequestMemory \n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(507, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Not enough memory", NULL);
            free(szCallBackURL);
            if (sig_value) free(sig_value);
            return FALSE;
        }
        BOOL fCompletionExpected = false;
        HRESULT hr = pHttpRequest->ReadEntityBody((void*)szrequest_body, request_size, false, &cbSent, &fCompletionExpected);
        // Test for an error.
        if (FAILED(hr))
        {
            #ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app);
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "error "<< hr << " on  pHttpRequest->ReadEntityBody processing POST\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
            #endif  //DEBUG_TO_TEMP
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(500, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Error on reading the body", NULL);
            free(szCallBackURL);
            if (sig_value) free(sig_value);
            return FALSE;
        }
        szrequest_body[cbSent] = '\0';
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app);
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "cbSent :" << cbSent << "szrequest_body: " << szrequest_body << "\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
    }

    if (subs->szSecret && sig_value)
    {
        //Getting the X-Signature and checking if the request is correctlky
        // neither CreateHMACHash nor CreateHMACHash2 gives the expected result
        /*PBYTE computed_sig_value = CreateHMACHash2(hashAlgId, pszsecret, (char*)szrequest_body);
        if (computed_sig_value == NULL)
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(404, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Signature validation failed", NULL);
            free(szCallBackURL);
            free(sig_value);
            return FALSE;
        }
        And the result needs to be converted to HEX
        stringToHexa();
        */

        #define SHA256_HASH_SIZE 32  // Seems that the result is every time 32
        uint8_t out[SHA256_HASH_SIZE];
        char computed_sig_value[SHA256_HASH_SIZE * 2 + 1];
        unsigned i;

        // Call hmac-sha256 function
        hmac_sha256(subs->szSecret, strlen(subs->szSecret), szrequest_body, strlen(szrequest_body), &out, sizeof(out));
     

        // Convert `out` to string with printf
        memset(&computed_sig_value, 0, sizeof(computed_sig_value));
        for (i = 0; i < sizeof(out); i++) {
            snprintf(&computed_sig_value[i * 2], 3, "%02x", out[i]);
        }
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "value: " << sig_value << "\ncomputed value: " << computed_sig_value << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        if (0 != strcmp(sig_value, computed_sig_value))
        {
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(404, "", 0, 0);
            SendTextMessageToWebHub(pHttpResponse, "Signature validation failed", NULL);
            free(szCallBackURL);
            free(sig_value);
            return FALSE;
        }
        free(sig_value);
    }
    
    // Save the notification for sending to the client throught thee WS connection
    AddNotificationsToSubscriptions(szWebSockedId, szCallBackURL, (char*)szrequest_body);
    LeaveCriticalSection(&SubscriptionsSection);
    free(szCallBackURL);
    pHttpResponse->SetStatus(204, "", 0, 0);
    SendTextMessageToWebHub(pHttpResponse, NULL, NULL);
    return TRUE;
}


BOOL CheckAndSendNotificationsToWebSocketClientIfNeeded(IN IHttpResponse* pHttpResponse, char* szWebSockedId)
{
    EnterCriticalSection(&SubscriptionsSection);

    struct WS_CONNECTION* ws = GetWSConnection(szWebSockedId);
    if (!ws || !ws->Subscriptions || ws->nSubscriptions < 1)
    {
        LeaveCriticalSection(&SubscriptionsSection);
        return FALSE;
    }
    size_t i_subs, i_notif;
    for (i_subs = 0; i_subs < ws->nSubscriptions; i_subs++)
    {        
        DWORD cbSent = 0;
        HRESULT hr;
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Checking if there are some notifications" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (!ws->Subscriptions[i_subs].Notifications || ws->Subscriptions[i_subs].nNotifications < 1)
            continue;
        for (i_notif = 0; i_notif < ws->Subscriptions[i_subs].nNotifications; i_notif++)
        {
            if (ws->Subscriptions[i_subs].Notifications[i_notif].dataPost)
            {
                cbSent = 0;
                hr = SendTextMessageToWebSocketClient(pHttpResponse, ws->Subscriptions[i_subs].Notifications[i_notif].dataPost, &cbSent);
#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "HRESULT data Post Success?: " << SUCCEEDED(hr) << " cdSent " << cbSent << "\n" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP

                if (FAILED(hr))
                {
                    LeaveCriticalSection(&SubscriptionsSection);
                    return FALSE;
                }
                FreeMemoryOfOneNotification(&ws->Subscriptions[i_subs], i_notif);
            }            
        }    
    }
    LeaveCriticalSection(&SubscriptionsSection);
    return TRUE;
}
#define MODE_SUBSCRIBE      0
#define MODE_UNSUBSCRIBE    1

BOOL ProcessValidationOfIntentRequestFromServer(IHttpResponse* pHttpResponse, IN IHttpRequest* pHttpRequest, char* szWebSockedId, PSTR szRequest, int mode)
{
    char sztopic[MAX_LENGTH_TOPIC], szsecret[MAX_LENGTH_SECRET], szXAPIKey[MAX_LENGTH_XAPIKEY],
        szchallenge[MAX_LENGTH_CHALLENGE];

    // The response is a text/plain
    // Set the "Content-Type" header.
    char szContentType[] = "text/plain;charset=UTF-8";
    HRESULT hr = pHttpResponse->SetHeader(HttpHeaderContentType, szContentType,(USHORT)strlen(szContentType), TRUE);
    // Test for an error.
    if (FAILED(hr))
    {
        // Set the error status.
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "Cannot set the Content-type header", NULL);
        return FALSE;
    }

    *sztopic = '\0';
    *szsecret = '\0';
    if (NULL == GetQueryParameter(sztopic, MAX_LENGTH_TOPIC, "hub.topic", szRequest) || *sztopic == '\0')
    {
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "hub.topic required", NULL);
        return FALSE;
    }
    if (NULL == GetQueryParameter(szsecret, MAX_LENGTH_SECRET, "hub.secret", szRequest) || *szsecret == '\0')
    {
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "hub.secret required", NULL);
        return FALSE;
    }
#ifdef DE_MOMENT_NO_HO_USEM
    if (NULL == GetQueryParameter(szXAPIKey, MAX_LENGTH_XAPIKEY, szXAPIKey_Param, szRequest) || *szXAPIKey == '\0')
    {
        char str[50];
        pHttpResponse->SetStatus(404, "", 0, 0);
        sprintf(str, "%s required", szXAPIKey_Param);
        SendTextMessageToWebHub(pHttpResponse, str, NULL);
        return FALSE;
    }    
#endif
    if (NULL == GetQueryParameter(szchallenge, MAX_LENGTH_CHALLENGE, "hub.challenge", szRequest) || *szchallenge == '\0')
    {
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "hub.challenge required", NULL);
        return FALSE;
    }
    char str[100];
    if (NULL == GetQueryParameter(str, 100, "hub.lease_seconds", szRequest) || *str == '\0')
    {
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "hub.lease_seconds required", NULL);
        return FALSE;
    }
    int lease_seconds = atoi(str);

    EnterCriticalSection(&SubscriptionsSection);
    char* szCallBackURL = GetCallBackURL(szTopic_Param, szRequest, szWebSockedId);
    if(!szCallBackURL)
    {        
        pHttpResponse->SetStatus(404, "", 0, 0);
        SendTextMessageToWebHub(pHttpResponse, "szCallBackURL required", NULL);
        LeaveCriticalSection(&SubscriptionsSection);
        return FALSE;
    }
    if (mode == MODE_UNSUBSCRIBE)
    {
        if (!DeleteSubscription(szWebSockedId, szCallBackURL))
        {
            char str[512];
            pHttpResponse->SetStatus(404, "", 0, 0);
            sprintf(str, "Subscription identified by \'%s\' not founded", szWebSockedId);
            SendTextMessageToWebHub(pHttpResponse, str, NULL);
            LeaveCriticalSection(&SubscriptionsSection);
            free(szCallBackURL);
            return FALSE;
        }
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Subscripció " << szWebSockedId << " esborrada" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
    }
    else
    {        
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Inici subscripció" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if(NULL==AddInfoToSusbcription(szWebSockedId, szCallBackURL, sztopic, szsecret, szXAPIKey, szchallenge, lease_seconds, TRUE))
        {
            char str[512];            
            LeaveCriticalSection(&SubscriptionsSection);
            pHttpResponse->SetStatus(404, "", 0, 0);    
            sprintf(str, "Subscription identified by \'%s\' not founded", szCallBackURL);
            SendTextMessageToWebHub(pHttpResponse, str, NULL);
            free(szCallBackURL);
            return FALSE;
        }
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "Subscripció "<< szCallBackURL << " del WebSocket "<< szWebSockedId << " feta per \n topic : " << sztopic << "\n secret : " << szsecret << "\n challenge : " << szchallenge << "\n lease_seconds : " << lease_seconds << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
    }
    LeaveCriticalSection(&SubscriptionsSection);
    free(szCallBackURL);
    pHttpResponse->SetStatus(202, "", 0, 0);
    SendTextMessageToWebHub(pHttpResponse, szchallenge, NULL);
    return TRUE;    
}


char *GetScriptName(IN IHttpContext* pHttpContext)
{
DWORD cbScriptName = 0;
char* pszScriptName = NULL;

    // Retrieve the script information.
    PCWSTR pwszScriptName = pHttpContext->GetScriptName(&cbScriptName); // Script Name : / wsmm / prova_llarge / kldskdls

    if ((pwszScriptName != NULL) && (cbScriptName > 0))
    {
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            char str[500];
            sprintf(str, "Script Name Length:  cbScriptName : %d strlen: %d", cbScriptName, (int)wcslen(pwszScriptName));
            outputFile << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        // Create a non-unicode buffer for the script information.
        pszScriptName = (char*)pHttpContext->AllocateRequestMemory(cbScriptName + 1);

        if (pszScriptName != NULL)
        {
            wcstombs(pszScriptName, pwszScriptName, cbScriptName);
            pszScriptName[cbScriptName] = '\0';
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app);
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Script Name: " << pszScriptName << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
        }
    }
    DeleteLastCharOfString(pszScriptName, '/');
    return pszScriptName;    
}

BOOL IsAWebHookHandShake(IN IHttpContext* pHttpContext, IN IHttpRequest* pHttpRequest)
{
PCSTR p;

    // Checking the HTTP version
    USHORT uMajorVersion;
    USHORT uMinorVersion;
    pHttpRequest->GetHttpVersion(&uMajorVersion, &uMinorVersion);
    if (uMajorVersion < 1 || (uMajorVersion == 1 && uMinorVersion < 1))
        return FALSE;

#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "HTTP version: " << uMajorVersion << "." << uMinorVersion << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP

    // Checking the header keys
    char *pszUpgrade, *pszConnection, *pszWebSocketKey, *pszWebSocketVersion;
    USHORT cchUpgrade = 0, cchConnection = 0, cchWebSocketKey = 0, cchWebSocketVersion = 0;

    // Upgrade : websocket
    pHttpRequest->GetHeader("Upgrade", &cchUpgrade);
    if (cchUpgrade < 1)
        return FALSE;
    // Retrieve the "Upgrade" header.
    if (NULL == (p = pHttpRequest->GetHeader("Upgrade", &cchUpgrade)))
        return FALSE;
    // Allocate space to store the header.
    if (NULL == (pszUpgrade = (char*)malloc((size_t)cchUpgrade + 1)))
        return FALSE;
    strcpy(pszUpgrade, p);

    // Test for an error.
    if (NULL == stristr(pszUpgrade, "websocket"))
    {
        free(pszUpgrade);
        return FALSE;
    }
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Upgrade: websocket " << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    free(pszUpgrade);

    // Connection: Upgrade
    pHttpRequest->GetHeader("Connection", &cchConnection);
    if (cchConnection < 1)
        return FALSE;
    // Retrieve the "Connection" header.
    if (NULL == (p = pHttpRequest->GetHeader("Connection", &cchConnection)))
        return FALSE;
    // Allocate space to store the header.
    if (NULL == (pszConnection = (char*)malloc((size_t)cchConnection + 1)))
        return FALSE;
    strcpy(pszConnection, p);

    // Test for an error.
    if (NULL == stristr(pszConnection, "Upgrade"))
    {
        free(pszConnection);
        return FALSE;
    }
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Connection: upgrade " << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    free(pszConnection);

    // Sec-WebSocket-Key
    pHttpRequest->GetHeader("Sec-WebSocket-Key", &cchWebSocketKey);
    if (cchWebSocketKey < 1)
        return FALSE;
    if (NULL == (p = pHttpRequest->GetHeader("Sec-WebSocket-Key", &cchConnection)))
        return FALSE;
    if (NULL == (pszWebSocketKey = (char*)malloc((size_t)cchWebSocketKey + 1)))
        return FALSE;
    strcpy(pszWebSocketKey, p);

#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Sec-WebSocket-Key: " << pszWebSocketKey << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    free(pszWebSocketKey);

    // Sec-WebSocket-Version : 13
    pHttpRequest->GetHeader("Sec-WebSocket-Version", &cchWebSocketVersion);
    if (cchWebSocketVersion < 1)
        return FALSE;
    if (NULL == (p = pHttpRequest->GetHeader("Sec-WebSocket-Version", &cchWebSocketVersion)))
        return FALSE;
    if (NULL == (pszWebSocketVersion = (char*)malloc((size_t)cchWebSocketVersion + 1)))
        return FALSE;
    strcpy(pszWebSocketVersion,p);
    
    // the version must be 13
    if (0 != strcmp(pszWebSocketVersion, "13"))
    {
        free(pszWebSocketVersion);
        return FALSE;
    }
#ifdef DEBUG_TO_TEMP
    outputFile.open(szDebugFile, std::ofstream::app); 
    if (outputFile.is_open()) { // check if the file was opened successfully
        outputFile << "Sec-WebSocket-Version: " << pszWebSocketVersion << std::endl; // write data to the file
        outputFile.close(); // close the file when done
    }
#endif  //DEBUG_TO_TEMP
    free(pszWebSocketVersion);
    return TRUE;
}


// Get the query of the request (the fullURL or the query string in KVP)
PSTR GetQuery(IN IHttpContext* pHttpContext, IN IHttpRequest* pHttpRequest)
{
    // Return the raw HTTP_REQUEST structure. (Defined in the Http.h file.)
    HTTP_REQUEST* pRawRequest = pHttpRequest->GetRawHttpRequest();
    PSTR szQueryString = NULL;
    size_t len = 0;
    if (pRawRequest->CookedUrl.pFullUrl)
    {
        // Allocate space for the configuration path.
        len = wcslen(pRawRequest->CookedUrl.pFullUrl);
        szQueryString = (PSTR)pHttpContext->AllocateRequestMemory((DWORD)len + 1);
        // Test for an error.
        if (NULL == szQueryString)
            return NULL;

        // Convert the WCHAR string to a CHAR string.
        wcstombs(szQueryString, pRawRequest->CookedUrl.pFullUrl, len);
        szQueryString[len] = '\0';

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "pRawRequest->CookedUrl.pFullUrl: " << szQueryString << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif DEBUG_TO_TEMP
        return szQueryString;
    }
    if (pRawRequest->CookedUrl.pQueryString)
    {
        // Allocate space for the configuration path.
        len = wcslen(pRawRequest->CookedUrl.pQueryString);
        szQueryString = (PSTR)pHttpContext->AllocateRequestMemory((DWORD)len + 1);

        // Test for an error.
        if (NULL == szQueryString)
            return NULL;

        // Convert the WCHAR string to a CHAR string.
        wcstombs(szQueryString, pRawRequest->CookedUrl.pQueryString, len);
        szQueryString[len] = '\0';

#ifdef DEBUG_TO_TEMP        
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "pRawRequest->_HTTP_COOKED_URL.pQueryString: " << szQueryString << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        return szQueryString;
    }
    return NULL;
}


// Create the module class.
class CWebSocketNative : public CHttpModule
{
private:

    bool isInAsyncRead=false;

    void* buffer=NULL;
    DWORD buffer_len = 10000;
    DWORD cbSent = 0;

    HRESULT hrBuffer = 0;
    DWORD cbReceiveBuffer = 0;
    BYTE *ReceiveBuffer=NULL;
    BOOL ShaCompletatAsynRequest = FALSE;
    CRITICAL_SECTION ReceiveBufferSection;
    
    BOOL ReceiveBufferInit = FALSE;

public:    
    REQUEST_NOTIFICATION_STATUS OnBeginRequest(
        IN IHttpContext* pHttpContext,
        IN IHttpEventProvider* pProvider
    )
    {
        UNREFERENCED_PARAMETER(pProvider);   

        if (!ReceiveBufferInit)
        {
            InitializeCriticalSection(&ReceiveBufferSection);
            EnterCriticalSection(&ReceiveBufferSection);
            isInAsyncRead = false;
            ReceiveBufferInit = TRUE;
            ShaCompletatAsynRequest = FALSE;
            LeaveCriticalSection(&ReceiveBufferSection);
        }

#ifdef DEBUG_TO_TEMP
        std::ofstream outputFile(szDebugFile, std::ofstream::app);
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            const auto now = std::chrono::system_clock::now();
            const std::time_t t_c = std::chrono::system_clock::to_time_t(now);
            char str[26];
            ctime_s(str, sizeof(str), &t_c);
            outputFile << "Start " << str << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        // Create an HRESULT to receive return values from methods.
        HRESULT hr;

        /* We can have two modes of REQUEST: GET and POST
        * 
        *  1) GET mode:
        * 
        *       1.1) Handshake from client to server: Connection request from client to WebSocket, we need the next information:
        * 
        *       - Request mode GET
        *       - HTTP version >= 1.1
        *       - Request-URI type: ws/wss://host[:port]/path?query
        *       - Request-headers:
        *               -Host: host[:port]
        *               -Upgrade: websocket
        *               -Connection: Upgrade
        *               -Wec-WebSocket-Key:
        *               -Sec-WebSocket-Version: 13
        * 
        *       1.2) Subscribe: From WebHub to WebHook: Validation of intent mode=subscribe
        *   
        *      Info from https://www.w3.org/TR/websub/#x5-1-subscriber-sends-subscription-request: 5.1 Subscriber Sends Subscription Request
        *      Subscription is initiated by the subscriber making an HTTPS or HTTP POST [RFC7231] request to the hub URL. 
        *      This request MUST have a Content-Type header of application/x-www-form-urlencoded (described in Section 4.10.22.6 [HTML5]), MUST use UTF-8 [Encoding] as the document character encoding, 
        *      and MUST use the following parameters in its body, formatted accordingly:
        *      hub.callback: REQUIRED. The subscriber's callback URL where content distribution notifications should be delivered. The callback URL SHOULD be an unguessable URL that is unique per subscription. ([capability-urls])
        *      hub.mode: REQUIRED. The literal string "subscribe" or "unsubscribe", depending on the goal of the request.
        *      hub.topic: REQUIRED. The topic URL that the subscriber wishes to subscribe to or unsubscribe from. Note that this MUST be the "self" URL found during the discovery step, which may be different from the URL that was used to make the discovery request.
        *      hub.lease_seconds: OPTIONAL. Number of seconds for which the subscriber would like to have the subscription active, given as a positive decimal integer. Hubs MAY choose to respect this value or not, depending on their own policies, and MAY set a default value if the subscriber omits the parameter. This parameter MAY be present for unsubscription requests and MUST be ignored by the hub in that case.
        *      hub.secret: OPTIONAL. A subscriber-provided cryptographically random unique secret string that will be used to compute an HMAC digest for authorized content distribution. If not supplied, the HMAC digest will not be present for content distribution requests. This parameter SHOULD only be specified when the request was made over HTTPS [RFC2818]. This parameter MUST be less than 200 bytes in length. 
        * 
        *        - Request mode GET
        *        - Query parameters: 
        *            hub.mode=subscribe
        *            hub.topic       
        *            hub.secret
        *            hub.challenge
        *            hub.lease-seconds
        *        - Request-headers: Això no va a la subscripció
        *           x-Hub-Signature
        * 
        *       1.3) Unsubscribe: From WebSub to WebHook: Validation of intent mode=unsubscribe
        * 
        *        - Request mode GET
        *        - Query parameters: 
        *            hub.mode=unsubscribe
        *            hub.topic        
        *            hub.secret
        *            hub.challenge
        *        - Request-headers: Això no va a la subscripció
        *           x-Hub-Signature
        *        
        *        
        *  2) POST mode: From WebSub to WebHook. We need to send the information to the client
        *       - Webhook.site setup Javascript Function Callback
        *       - Request-headers:
        *           x-Hub-Signature
        */        

        // Retrieve a pointer to the response.
        IHttpResponse* pHttpResponse = pHttpContext->GetResponse();
        if (!pHttpResponse)
        {
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
        // Clear the existing response.
        pHttpResponse->Clear();

        // Retrieve a pointer to the request.
        IHttpRequest* pHttpRequest = pHttpContext->GetRequest();
        if (!pHttpRequest)
        {
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }

        //Retrieve the URL or the query string of the request
        PSTR szquery = GetQuery(pHttpContext, pHttpRequest);
        if(szquery==NULL)
        {
            // Set the error status.
            hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
            pProvider->SetErrorStatus(hr);
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "query string: " << szquery << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        // Retrieve the HTTP method.
        LPCSTR pszHttpMethod = pHttpRequest->GetHttpMethod();
        if (!pszHttpMethod)
        {
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "REQUEST method: " << pszHttpMethod << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        // SCRIPT NAME: We are using the scriptName how a Socket Identifier    

        // Retrieve the script information.
        char* pszScriptName = GetScriptName(pHttpContext);
        if (!pszScriptName)
        {
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "pszScriptName: " << pszScriptName << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP        

        // POST requests
        if (0 == _stricmp(pszHttpMethod, "POST"))
        {
            ProcessPostRequestFromServer(pHttpContext, pHttpResponse, pHttpRequest, szquery, pszScriptName);
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
        else if (0 != _stricmp(pszHttpMethod, "GET"))
        {
            pHttpResponse->SetStatus(405, "", 0, 0);
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        } 
        
        // GET requests
        /* 1) Handshake from client to server : Websocket connection from client to webhook
        *  2) Subscription
        *  3) Unsubscription */

        #define MAX_VALUE_LENGTH 250
        char value[MAX_VALUE_LENGTH];
        size_t value_size = MAX_VALUE_LENGTH;
        *value = '\0';
        if (GetQueryParameter(value, value_size, "hub.mode", szquery))
        {
            if (0 == _stricmp(value, "subscribe"))
            {
#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "M'ha arribat un ValidationOfIntent de tipus subscribe" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP
                ProcessValidationOfIntentRequestFromServer(pHttpResponse, pHttpRequest, pszScriptName, szquery, MODE_SUBSCRIBE);                    
                DeleteCriticalSection(&ReceiveBufferSection);
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }
            else if (0 == _stricmp(value, "unsubscribe"))
            {
#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "M'ha arribat un ValidationOfIntent de tipus UNsubscribe" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP
                ProcessValidationOfIntentRequestFromServer(pHttpResponse, pHttpRequest, pszScriptName, szquery, MODE_UNSUBSCRIBE);                    
                DeleteCriticalSection(&ReceiveBufferSection);
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }
        }

        // Handshake from client to server ?
        if(!IsAWebHookHandShake(pHttpContext, pHttpRequest))
        {
            // We have a GET that don't understand
            pHttpResponse->SetStatus(406, "", 0, 0); 
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }

#ifdef TEST_SERVER_VARIABLES
        // En principi aquesta funció hauria de retornar les variables del servidor de la mateixa manera que fem en una CGI
        // però no m'ha funcionat.  // SCRIPT_NAME" | "SERVER_NAME" |
        PCSTR* ppszValue = NULL;
        DWORD pcchValueLength = 0;
        pHttpContext->GetServerVariable("QUERY_STRING", ppszValue, &pcchValueLength);
        if (pcchValueLength > 0)
        {
            ppszValue = (PCSTR*)pHttpContext->AllocateRequestMemory(pcchValueLength + 1);
            hr = pHttpContext->GetServerVariable("QUERY_STRING", ppszValue, &pcchValueLength);
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "QUERY_STRING var: " << ppszValue << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
        }

        // Això si i m'ha retornat c:\Inetpub\wwwroot
        // Length of the returned path.
        DWORD cbPhysicalPath = 0;

        // Get the length of the mapped path.
        pHttpContext->MapPath(L"/", NULL, &cbPhysicalPath);

        if (cbPhysicalPath > 0)
        {
            // Allocate space to store the path.
            PWSTR pwszPhysicalPath =
                (PWSTR)pHttpContext->AllocateRequestMemory(cbPhysicalPath + 1);
            PSTR pszPhysicalPath =
                (PSTR)pHttpContext->AllocateRequestMemory(cbPhysicalPath + 1);

            // Retrieve the mapped path.
            pHttpContext->MapPath(L"/", pwszPhysicalPath, &cbPhysicalPath);

            // Convert the WCHAR string to a CHAR string.
            wcstombs_s((size_t*)&cbPhysicalPath, pszPhysicalPath,
                cbPhysicalPath, pwszPhysicalPath, cbPhysicalPath);
    #ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "pHttpContext->MapPath var: " << pszPhysicalPath << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
    #endif  //DEBUG_TO_TEMP
        }

        // Ara he de mirar el path per desar-me l'identificador del socket
        // Retrieve a pointer to the IMetadataInfo interface.
        // Això m'ha retornat:  Config Path (metadata): MACHINE/WEBROOT/APPHOST/DEFAULT WEB SITE/WSMM
        IMetadataInfo* pMetadataInfo = pHttpContext->GetMetadata();
        if (pMetadataInfo)
        {
            // Retrieve the configuration path.
            PCWSTR pwszConfigPath = pMetadataInfo->GetMetaPath();

            // Allocate space for the configuration path.
            PSTR pszConfigPath =
                (PSTR)pHttpContext->AllocateRequestMemory(
                    (DWORD)wcslen(pwszConfigPath) + 1);

            // Test for an error.
            if (NULL == pszConfigPath)
            {
                // Set the error status.
                hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
                pProvider->SetErrorStatus(hr);
                // End additional processing.
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }

            // Convert the WCHAR string to a CHAR string.
            wcstombs(pszConfigPath,
                pwszConfigPath, wcslen(pwszConfigPath));
            pszConfigPath[wcslen(pwszConfigPath)] = '\0';

#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Config Path (metadata): " << pszConfigPath << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
        }

        // Això m'ha retornat : Physical Path : C:\inetpub\wwwroot\WSMM\prova_path_var1\paht2
        PCWSTR pwszPhysicalPath = NULL;
        char* pszPhysicalPath = NULL;
        // Length of the string returned.
        DWORD  cchPhysicalPath = 0;

        // Retrieve the physical path.
        pwszPhysicalPath = pHttpContext->GetPhysicalPath(&cchPhysicalPath);
        if (cchPhysicalPath > 0)
        {
            // Retrieve the physical path.
            PSTR pszPhysicalPath =
                (PSTR)pHttpContext->AllocateRequestMemory(
                    (DWORD)wcslen(pwszPhysicalPath) + 1);

            // Test for an error.
            if (NULL == pszPhysicalPath)
            {
                // Set the error status.
                hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
                pProvider->SetErrorStatus(hr);
                // End additional processing.
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }

            // Convert the WCHAR string to a CHAR string.
            wcstombs(pszPhysicalPath,
                pwszPhysicalPath, wcslen(pwszPhysicalPath));
            pszPhysicalPath[wcslen(pwszPhysicalPath)] = '\0';

#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "Physical Path : " << pszPhysicalPath << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP
        }

        // Get a pointer to an IHttpFileInfo class.
        // Això crec que no ha funcionat
        IHttpFileInfo* pHttpFileInfo = pHttpContext->GetFileInfo();

        if (NULL != pHttpFileInfo)
        {
            // Create pointers for the file path.
            PCWSTR pwszFilePath;
            char* pszFilePath;
            // Retrieve the file path.
            pwszFilePath = pHttpFileInfo->GetFilePath();

            // Test for an error.
            if (pwszFilePath != NULL)
            {
                pszFilePath = (char*)pHttpContext->AllocateRequestMemory((DWORD)wcslen(pwszFilePath));
                wcstombs(pszFilePath, pwszFilePath, wcslen(pwszFilePath));
                pszFilePath[wcslen(pwszFilePath)] = '\0';

#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "File Path : " << pszFilePath << "\n" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP
            }
        }

        DWORD cbScriptTranslated = 0;
        PCWSTR pwszScriptTranslated = pHttpContext->GetScriptTranslated(&cbScriptTranslated); // Script Translated : C:\inetpub\wwwroot\WSMM\prova_llarge\kldskdls
        // Test for an error.
        if ((pwszScriptTranslated != NULL) && (cbScriptTranslated > 0))
        {
            // Create a non-unicode buffer for the script information.
            char* pszScriptTranslated = (char*)pHttpContext->AllocateRequestMemory(cbScriptTranslated + 1);
            // Test for an error.
            if (pwszScriptTranslated != NULL && pszScriptTranslated != NULL)
            {
                // Send the script information to the client.
                wcstombs(pszScriptTranslated, pwszScriptTranslated, cbScriptTranslated);
                pszScriptTranslated[cbScriptTranslated] = '\0';

#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "Script Translated: " << pszScriptTranslated << "\n" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP
            }
        }

#endif // TEST_SERVER_VARIABLES

        // Creo una nova subscripció de la qual encara no tinc gaire informació
        EnterCriticalSection(&SubscriptionsSection);
        size_t i_connec=PushNewWSConnection(pszScriptName);
        LeaveCriticalSection(&SubscriptionsSection);

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "CONNECTION: " << pszScriptName << " created "<<"\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        // Envio la resposta dient que la connexió s'ha establert
        pHttpResponse->Clear();

        pHttpResponse->SetStatus(101, "Switching Protocols");
        pHttpResponse->SetHeader(
            HttpHeaderUpgrade, "websocket",
            (USHORT)strlen("websocket"), TRUE);
        pHttpResponse->SetHeader(
            HttpHeaderConnection, "Upgrade",
            (USHORT)strlen("Upgrade"), TRUE);

        /* From https://datatracker.ietf.org/doc/html/rfc6455:
        To prove that the handshake was received, the server has to take two
        pieces of information and combine them to form a response.  The first
        piece of information comes from the |Sec-WebSocket-Key| header field
        in the client handshake:

            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

        For this header field, the server has to take the value (as present
        in the header field, e.g., the base64-encoded [RFC4648] version minus
        any leading and trailing whitespace) and concatenate this with the
        Globally Unique Identifier (GUID, [RFC4122]) "258EAFA5-E914-47DA-
        95CA-C5AB0DC85B11" in string form, which is unlikely to be used by
        network endpoints that do not understand the WebSocket Protocol.  A
        SHA-1 hash (160 bits) [FIPS.180-3], base64-encoded (see Section 4 of
        [RFC4648]), of this concatenation is then returned in the server's
        handshake.*/
            
        BOOL fCompletionExpected = false;
        hr = pHttpResponse->Flush(false, true, &cbSent, &fCompletionExpected);

#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "HRESULT Flush Success?: " << SUCCEEDED(hr) << "\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP

        if (FAILED(hr))
        {
            // Set the HTTP status.
            pHttpResponse->SetStatus(500, "Server Error", 0, hr);
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
        // i deixo el canal obert per anar comunicant-me amb el client
        Sleep(100);

        //Si en lloc d'escriure volem llegir s'ha de fer servir ReadEntityBody()
        /*
        IHttpContext3* pHttpContext3;
        HttpGetExtendedInterface(g_pHttpServer, pHttpContext, &pHttpContext3);

        pHttpContext3->EnableFullDuplex();

        //IWebSocketContext* cts = (IWebSocketContext*)pHttpContext3->GetNamedContextContainer()->GetNamedContext(L"websockets");
        */
        LPSTR UTF8Str = NULL;
        size_t cchUTF8Str = 0;
#ifdef TEST
        if (ExpandAndCopyUTF8FromChar(&UTF8Str, &cchUTF8Str, "N£ria Juli…"))
        {
            hr = SendTextMessageToWebSocketClient(pHttpResponse, UTF8Str, &cbSent);
            //hr = SendTextMessageToWebSocketClient(pHttpResponse, "Marta Muntada", &cbSent);
            if (FAILED(hr))
            {
                // Set the HTTP status.
                if (UTF8Str) { free(UTF8Str); UTF8Str = NULL; }
                cchUTF8Str = 0;
                SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);
                DeleteCriticalSection(&ReceiveBufferSection);
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }
        }
#endif
        char szmsg[512];
        std::sprintf(szmsg, "WebHook Identifier : %s", pszScriptName);      
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "WebHook Id?: " << szmsg << "\n" << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }
#endif  //DEBUG_TO_TEMP
        if (ExpandAndCopyUTF8FromChar(&UTF8Str, &cchUTF8Str, szmsg))
        {
            hr = SendTextMessageToWebSocketClient(pHttpResponse, UTF8Str, &cbSent);
            //hr = SendTextMessageToWebSocketClient(pHttpResponse, szmsg, &cbSent);

#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "HRESULT Success?: " << SUCCEEDED(hr) << " cdSent " << cbSent << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP

            if (FAILED(hr))
            {
                // Set the HTTP status.
                if (UTF8Str) { free(UTF8Str); UTF8Str = NULL; }
                cchUTF8Str = 0;
                SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);
                DeleteCriticalSection(&ReceiveBufferSection);
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }
        }
#ifdef TEST
        Sleep(100);
        if (ExpandAndCopyUTF8FromChar(&UTF8Str, &cchUTF8Str, "Our Father, who art in heaven, hallowed be thy name; thy kingdom come; thy will be done; on earth as it is in heaven.Give us this day our daily bread.And forgive us our trespasses, as we forgive those who trespass against us.And lead us not into temptation; but deliver us from evil"))
        {
            hr = SendTextMessageToWebSocketClient(pHttpResponse, UTF8Str, &cbSent);
            //hr = SendTextMessageToWebSocketClient(pHttpResponse, "Our Father, who art in heaven, hallowed be thy name; thy kingdom come; thy will be done; on earth as it is in heaven.Give us this day our daily bread.And forgive us our trespasses, as we forgive those who trespass against us.And lead us not into temptation; but deliver us from evil", &cbSent);
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "HRESULT Success?: " << SUCCEEDED(hr) << " cdSent " << cbSent << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP

            if (FAILED(hr))
            {
                // Set the HTTP status.
                if (UTF8Str) { free(UTF8Str); UTF8Str = NULL; }
                cchUTF8Str = 0;
                SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);
                DeleteCriticalSection(&ReceiveBufferSection);
                return RQ_NOTIFICATION_FINISH_REQUEST;
            }
        }
#endif
        if (UTF8Str) { free(UTF8Str); UTF8Str = NULL; }
        cchUTF8Str = 0;
        if (NULL == (buffer = pHttpContext->AllocateRequestMemory(buffer_len)))
        {
            SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);
            DeleteCriticalSection(&ReceiveBufferSection);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }

        do {
            Sleep(100);
            bool completionPending = false;

            if (!isInAsyncRead)
            {
                EnterCriticalSection(&ReceiveBufferSection);
                if (ShaCompletatAsynRequest)
                {                                                
                    // Test for an error.
                    if (FAILED(hrBuffer))
                    {
                        // End of data is okay.
                        if (ERROR_HANDLE_EOF != (hr & 0x0000FFFF))
                        {
                            // Set the error status.
                            //pProvider->SetErrorStatus(hr);
                            SendFlagMessageToWebSocketClient(pHttpResponse, FIRST_BYTE_OPCODE_CLOSECONNECTION);
                            // End additional processing.
                            LeaveCriticalSection(&ReceiveBufferSection);
                            DeleteCriticalSection(&ReceiveBufferSection);
                            return RQ_NOTIFICATION_FINISH_REQUEST;
                        }
                    }
                    if (ReceiveBuffer)
                    {
                        if (ProcessRequestToWebSocketClient(pHttpResponse, ReceiveBuffer, cbReceiveBuffer))
                        {
                            free(ReceiveBuffer);
                            ReceiveBuffer = NULL;
                            cbReceiveBuffer = 0;
                            LeaveCriticalSection(&ReceiveBufferSection);
                            DeleteCriticalSection(&ReceiveBufferSection);
                            return RQ_NOTIFICATION_FINISH_REQUEST;
                        }
                        free(ReceiveBuffer);
                        ReceiveBuffer = NULL;
                        cbReceiveBuffer = 0;
                    }
                    
                    ShaCompletatAsynRequest = FALSE;
                }
                LeaveCriticalSection(&ReceiveBufferSection);
                
                isInAsyncRead = true;
                pHttpRequest->ReadEntityBody(
                    buffer,
                    buffer_len,
                    true,  //true
                    &cbSent,
                    &fCompletionExpected
                );
            }

            CheckAndSendNotificationsToWebSocketClientIfNeeded(pHttpResponse, pszScriptName);
#ifdef DEBUG_TO_TEMP
            outputFile.open(szDebugFile, std::ofstream::app); 
            if (outputFile.is_open()) { // check if the file was opened successfully
                outputFile << "ReadEntityBody HRESULT Success?: " << SUCCEEDED(hr) << " eof?: " << (ERROR_HANDLE_EOF == (hr & 0x0000FFFF) ? "true" : "false") << " cdSent " << cbSent << "\n" << std::endl; // write data to the file
                outputFile.close(); // close the file when done
            }
#endif  //DEBUG_TO_TEMP

        } while (true);


        // https://jennylaw.azurewebsites.net/posts/iis-native-module-development/
        // Tell IIS to keep the connection pending...
        DeleteCriticalSection(&ReceiveBufferSection);
        return RQ_NOTIFICATION_PENDING;
        
        /* Si no hi havia alguna cosa que m'interessava he tancat el canal
        // Return processing to the pipeline.
        DeleteCriticalSection(&ReceiveBufferSection);
        return RQ_NOTIFICATION_CONTINUE;
        */
    }

    REQUEST_NOTIFICATION_STATUS OnAsyncCompletion(
        IN IHttpContext* pHttpContext,
        IN DWORD dwNotification,
        IN BOOL fPostNotification,
        IN OUT IHttpEventProvider* pProvider,
        IN IHttpCompletionInfo* pCompletionInfo
    )
    {        
#ifdef DEBUG_TO_TEMP
        outputFile.open(szDebugFile, std::ofstream::app); 
        if (outputFile.is_open()) { // check if the file was opened successfully
            outputFile << "HRESULT OnAsyncCompletion a dins: "  << std::endl; // write data to the file
            outputFile.close(); // close the file when done
        }        
#endif  //DEBUG_TO_TEMP

        if (pCompletionInfo != NULL)
        {
            if (ReceiveBufferInit)
            {
                EnterCriticalSection(&ReceiveBufferSection);

                hrBuffer = pCompletionInfo->GetCompletionStatus();
                cbReceiveBuffer = min(buffer_len, pCompletionInfo->GetCompletionBytes());
            
                if (cbReceiveBuffer > 0)
                {
                    if(NULL!=(ReceiveBuffer = (BYTE*)malloc(cbReceiveBuffer)))
                        memcpy(ReceiveBuffer, buffer, cbReceiveBuffer);
                }
#ifdef DEBUG_TO_TEMP
                outputFile.open(szDebugFile, std::ofstream::app); 
                if (outputFile.is_open()) { // check if the file was opened successfully
                    outputFile << "OnAsyncCompletion acabat ? :" <<  "\n" << std::endl; // write data to the file
                    outputFile.close(); // close the file when done
                }
#endif  //DEBUG_TO_TEMP
                ShaCompletatAsynRequest = TRUE;
                LeaveCriticalSection(&ReceiveBufferSection);
            }
            isInAsyncRead = false;
            return RQ_NOTIFICATION_PENDING;
        }
        // Return processing to the pipeline.
        isInAsyncRead = false;
        return RQ_NOTIFICATION_PENDING;
    }
};

// Create the module's class factory.
class CWebSocketNativeFactory : public IHttpModuleFactory
{
public:
    HRESULT
        GetHttpModule(
            OUT CHttpModule** ppModule,
            IN IModuleAllocator* pAllocator
        )
    {
        UNREFERENCED_PARAMETER(pAllocator);

        // Init the global variables --> Subscriptions array
        InitializeCriticalSection(&SubscriptionsSection);
        EnterCriticalSection(&SubscriptionsSection);        
        if(NULL== GetMemoryWSConnectionIfNeeded())
        {
            LeaveCriticalSection(&SubscriptionsSection);
            DeleteCriticalSection(&SubscriptionsSection);
            return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        }
        LeaveCriticalSection(&SubscriptionsSection);

        // Create a new instance.
        CWebSocketNative* pModule = new CWebSocketNative;

        // Test for an error.
        if (!pModule)
        {
            // Return an error if the factory cannot create the instance.
            return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        }
        else
        {
            // Return a pointer to the module.
            *ppModule = pModule;
            pModule = NULL;
            // Return a success status.
            return S_OK;
        }
    }

    void
        Terminate()
    {
        // Removing the memory from the global variables
        EnterCriticalSection(&SubscriptionsSection);
        FreeMemoryAllWSConnections();
        LeaveCriticalSection(&SubscriptionsSection);
        DeleteCriticalSection(&SubscriptionsSection);

        // Remove the class from memory.
        delete this;
    }
};

// Create the module's exported registration function.
HRESULT
__stdcall
RegisterModule(
    DWORD dwServerVersion,
    IHttpModuleRegistrationInfo* pModuleInfo,
    IHttpServer* pHttpServer
)
{
    UNREFERENCED_PARAMETER(dwServerVersion);
    UNREFERENCED_PARAMETER(pHttpServer);

    // g_pHttpServer = pHttpServer;

    //https://fossies.org/linux/modsecurity/iis/main.cpp
    /* step 1: save the IHttpServer and the module context id for future use
        g_pModuleContext = pModuleInfo->GetId();
        g_pHttpServer = pHttpServer;
    // step 2: create the module factory
    //
    pFactory = new CMyHttpModuleFactory();
    if ( pFactory == NULL )
    {
        hr = HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY );
        goto Finished;
    }
 
    // step 3: register for server events
    //
    hr = pModuleInfo->SetRequestNotifications( pFactory, // module factory 
                                                    RQ_BEGIN_REQUEST | RQ_SEND_RESPONSE // server event mask,
                                                    RQ_END_REQUEST); // server post event mask
    if ( FAILED( hr ) )
    {
        goto Finished;
    }
 
    hr = pModuleInfo->SetPriorityForRequestNotification(RQ_BEGIN_REQUEST, PRIORITY_ALIAS_FIRST);
    hr = pModuleInfo->SetPriorityForRequestNotification(RQ_SEND_RESPONSE, PRIORITY_ALIAS_LAST); // reverted!
    */

    // Set the request notifications and exit.
    return pModuleInfo->SetRequestNotifications(
        new CWebSocketNativeFactory,
        RQ_BEGIN_REQUEST,
        0
    );
}
