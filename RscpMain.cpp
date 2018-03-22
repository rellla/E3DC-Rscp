#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include "e3dc_config.h"
#include "RscpProtocol.h"
#include "RscpTags.h"
#include "SocketConnection.h"
#include "AES.h"

static int iSocket = -1;
static int iAuthenticated = 0;
static AES aesEncrypter;
static AES aesDecrypter;
static uint8_t ucEncryptionIV[AES_BLOCK_SIZE];
static uint8_t ucDecryptionIV[AES_BLOCK_SIZE];

int createAuthRequest(SRscpFrameBuffer * frameBuffer, e3dc_config_t *e3dc_config)
{
    RscpProtocol protocol;
    SRscpValue rootValue;
    // The root container is create with the TAG ID 0 which is not used by any device.
    protocol.createContainerValue(&rootValue, 0);

    //---------------------------------------------------------------------------------------------------------
    // Create a auth request frame
    //---------------------------------------------------------------------------------------------------------
    printf("\nRequest authentication\n");
    // authentication request
    SRscpValue authenContainer;
    protocol.createContainerValue(&authenContainer,
				  TAG_RSCP_REQ_AUTHENTICATION);
    protocol.appendValue(&authenContainer, TAG_RSCP_AUTHENTICATION_USER,
			 e3dc_config->e3dc_user);
    protocol.appendValue(&authenContainer,
			 TAG_RSCP_AUTHENTICATION_PASSWORD, e3dc_config->e3dc_password);
    // append sub-container to root container
    protocol.appendValue(&rootValue, authenContainer);
    // free memory of sub-container as it is now copied to rootValue
    protocol.destroyValueData(authenContainer);

    // create buffer frame to send data to the S10
    protocol.createFrameAsBuffer(frameBuffer, rootValue.data, rootValue.length, true);	// true to calculate CRC on for transfer
    // the root value object should be destroyed after the data is copied into the frameBuffer and is not needed anymore
    protocol.destroyValueData(rootValue);

    return 0;
}

int createRequest(SRscpFrameBuffer * frameBuffer, int requests)
{
    RscpProtocol protocol;
    SRscpValue rootValue;
    // The root container is create with the TAG ID 0 which is not used by any device.
    protocol.createContainerValue(&rootValue, 0);

    //---------------------------------------------------------------------------------------------------------
    // Create a request frame
    //---------------------------------------------------------------------------------------------------------
    printf("\nRequest data:\n");

    // request power data information
    if (requests & TAG_EMS) {
	protocol.appendValue(&rootValue, TAG_EMS_REQ_POWER_PV);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_POWER_BAT);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_POWER_HOME);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_POWER_GRID);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_POWER_ADD);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_GET_POWER_SETTINGS);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_STATUS);
	protocol.appendValue(&rootValue, TAG_EMS_REQ_MODE);
    }

    // request idle periods information
    if (requests & TAG_GET_IDLE_PERIODS) {
	protocol.appendValue(&rootValue, TAG_EMS_REQ_GET_IDLE_PERIODS);
    }

    // request battery information
    if (requests & TAG_BATTERY) {
	SRscpValue batteryContainer;
	protocol.createContainerValue(&batteryContainer, TAG_BAT_REQ_DATA);
	protocol.appendValue(&batteryContainer, TAG_BAT_INDEX, (uint8_t) 0);
	protocol.appendValue(&batteryContainer, TAG_BAT_REQ_RSOC);
	protocol.appendValue(&batteryContainer, TAG_BAT_REQ_MODULE_VOLTAGE);
	protocol.appendValue(&batteryContainer, TAG_BAT_REQ_CURRENT);
	protocol.appendValue(&batteryContainer, TAG_BAT_REQ_STATUS_CODE);
	protocol.appendValue(&batteryContainer, TAG_BAT_REQ_ERROR_CODE);
	// append sub-container to root container
	protocol.appendValue(&rootValue, batteryContainer);
	// free memory of sub-container as it is now copied to rootValue
	protocol.destroyValueData(batteryContainer);
    }

    // request some more power data information
    if (requests & TAG_WEATHER_ENABLE) {
	SRscpValue powerContainer;
	uint8_t enable = !!(requests & TAG_WEATHER_ENABLE_F);
	protocol.createContainerValue(&powerContainer,
				      TAG_EMS_REQ_SET_POWER_SETTINGS);
	protocol.appendValue(&powerContainer,
			     TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED,
			     enable);
	protocol.appendValue(&rootValue, powerContainer);
	protocol.destroyValueData(powerContainer);
    }

    // request setting idle periods
    // this is WIP and some example values are hardcoded for now
    // this is not useable for productive environments atm
    if (requests & TAG_SET_IDLE_PERIODS) {
	SRscpValue setTimeContainer;
	protocol.createContainerValue(&setTimeContainer,
				      TAG_EMS_REQ_SET_IDLE_PERIODS);

	    SRscpValue setDayContainer;
	    protocol.createContainerValue(&setDayContainer,
					  TAG_EMS_IDLE_PERIOD);
	    protocol.appendValue(&setDayContainer,
				 TAG_EMS_IDLE_PERIOD_TYPE, (uint8_t)LOAD);
	    protocol.appendValue(&setDayContainer,
				 TAG_EMS_IDLE_PERIOD_DAY, (uint8_t)TUESDAY);
	    protocol.appendValue(&setDayContainer,
				 TAG_EMS_IDLE_PERIOD_ACTIVE, (bool)ACTIVE);

		SRscpValue setStartContainer;
		protocol.createContainerValue(&setStartContainer,
					  TAG_EMS_IDLE_PERIOD_START);
		protocol.appendValue(&setStartContainer,
				 TAG_EMS_IDLE_PERIOD_MINUTE, (uint8_t)00);
		protocol.appendValue(&setStartContainer,
				 TAG_EMS_IDLE_PERIOD_HOUR, (uint8_t)11);
		protocol.appendValue(&setDayContainer, setStartContainer);
		protocol.destroyValueData(setStartContainer);

		SRscpValue setStopContainer;
		protocol.createContainerValue(&setStopContainer,
					  TAG_EMS_IDLE_PERIOD_END);
		protocol.appendValue(&setStopContainer,
				 TAG_EMS_IDLE_PERIOD_MINUTE, (uint8_t)42);
		protocol.appendValue(&setStopContainer,
				 TAG_EMS_IDLE_PERIOD_HOUR, (uint8_t)12);
		protocol.appendValue(&setDayContainer, setStopContainer);
		protocol.destroyValueData(setStopContainer);

	    protocol.appendValue(&setTimeContainer, setDayContainer);
	    protocol.destroyValueData(setDayContainer);

	protocol.appendValue(&rootValue, setTimeContainer);
	protocol.destroyValueData(setTimeContainer);
    }

    // create buffer frame to send data to the S10
    protocol.createFrameAsBuffer(frameBuffer, rootValue.data, rootValue.length, true);	// true to calculate CRC on for transfer
    // the root value object should be destroyed after the data is copied into the frameBuffer and is not needed anymore
    protocol.destroyValueData(rootValue);

    return 0;
}

int
handleResponseEMSGetIdlePeriods(RscpProtocol * protocol,
				SRscpValue * emsData,
				idle_period_t *periods)
{
    // check each idle periods sub tag
    switch (emsData->tag) {
    case TAG_EMS_IDLE_PERIOD:{
	    std::vector < SRscpValue > idleData =
		protocol->getValueAsContainer(emsData);
	    // check each idle period sub tag
	    for (size_t j = 0; j < idleData.size(); ++j) {
		if (idleData[j].dataType == RSCP::eTypeError) {
		    // handle error for example access denied errors
		    uint32_t uiErrorCode =
			protocol->getValueAsUInt32(&idleData[j]);
		    printf("Tag 0x%08X received error code %u.\n",
			   idleData[j].tag, uiErrorCode);
		    return -1;
		}
		switch (idleData[j].tag) {
		case TAG_EMS_IDLE_PERIOD_TYPE:{
			periods->type = protocol->getValueAsUChar8(&idleData[j]);
			break;
		    }
		case TAG_EMS_IDLE_PERIOD_DAY:{
			periods->day = protocol->getValueAsUChar8(&idleData[j]);
			break;
		    }
		case TAG_EMS_IDLE_PERIOD_ACTIVE:{
			periods->active = protocol->getValueAsUChar8(&idleData[j]);
			break;
		    }
		case TAG_EMS_IDLE_PERIOD_START:{
			std::vector < SRscpValue >
			    periodData =
			    protocol->getValueAsContainer(&idleData[j]);
			// check each idle period start sub tag
			for (size_t k = 0; k < periodData.size(); ++k) {
			    if (periodData[k].dataType == RSCP::eTypeError) {
				// handle error for example access denied errors
				uint32_t
				    uiErrorCode =
				    protocol->getValueAsUInt32(&periodData
							       [k]);
				printf
				    ("Tag 0x%08X received error code %u.\n",
				     periodData[k].tag, uiErrorCode);
				return -1;
			    }
			    switch (periodData[k].tag) {
			    case TAG_EMS_IDLE_PERIOD_HOUR:{
				    periods->start.hour =
					protocol->getValueAsUChar8
					(&periodData[k]);
				    break;
				}
			    case TAG_EMS_IDLE_PERIOD_MINUTE:{
				    periods->start.minute =
					protocol->getValueAsUChar8
					(&periodData[k]);
				    break;
				}
			    default:
				// default behaviour
				uint8_t unknown =
				    protocol->getValueAsUChar8(&periodData
							       [k]);
				printf("Unknown period tag %08X -> %i.\n",
				       periodData[k].tag, unknown);
				break;
			    }
			}
			break;
		    }
		case TAG_EMS_IDLE_PERIOD_END:{
			std::vector < SRscpValue >
			    periodData =
			    protocol->getValueAsContainer(&idleData[j]);
			// check each idle period stop sub tag
			for (size_t k = 0; k < periodData.size(); ++k) {
			    if (periodData[k].dataType == RSCP::eTypeError) {
				// handle error for example access denied errors
				uint32_t
				    uiErrorCode =
				    protocol->getValueAsUInt32(&periodData
							       [k]);
				printf
				    ("Tag 0x%08X received error code %u.\n",
				     periodData[k].tag, uiErrorCode);
				return -1;
			    }
			    switch (periodData[k].tag) {
			    case TAG_EMS_IDLE_PERIOD_HOUR:{
				    periods->stop.hour =
					protocol->getValueAsUChar8
					(&periodData[k]);
				    break;
				}
			    case TAG_EMS_IDLE_PERIOD_MINUTE:{
				    periods->stop.minute =
					protocol->getValueAsUChar8
					(&periodData[k]);
				    break;
				}
			    default:
				// default behaviour
				uint8_t unknown =
				    protocol->getValueAsUChar8(&periodData
							       [k]);
				printf("Unknown period tag %08X -> %i.\n",
				       periodData[k].tag, unknown);
				break;
			    }
			}
			break;
		    }
		}
	    }
	    // print idle periods summary
	    if (periods->day == MONDAY)
		printf("Monday:     \t");
	    else if (periods->day == TUESDAY)
		printf("Tuesday:    \t");
	    else if (periods->day == WEDNESDAY)
		printf("Wednesday:  \t");
	    else if (periods->day == THURSDAY)
		printf("Thursday:   \t");
	    else if (periods->day == FRIDAY)
		printf("Friday:     \t");
	    else if (periods->day == SATURDAY)
		printf("Saturday:   \t");
	    else if (periods->day == SUNDAY)
		printf("Sunday:     \t");
	    else
		printf("Unknown day:\t");

	    if (periods->type == LOAD)
		printf("Ladesperre ");
	    else if (periods->type == UNLOAD)
		printf("Entladesperre ");
	    else
		printf("Unknown type!");

	    if (periods->active == ACTIVE)
		printf
		    ("aktiv von %02i:%02i - %02i:%02i",
		     periods->start.hour, periods->start.minute, periods->stop.hour, periods->stop.minute);
	    else if (periods->active == INACTIVE)
		printf
		    ("inaktiv (%02i:%02i - %02i:%02i)",
		     periods->start.hour, periods->start.minute, periods->stop.hour, periods->stop.minute);
	    else
		printf("Activity unknown! ");
	    printf("\n");
	    break;
	}
    default:
	// default behaviour
	uint8_t unknown = protocol->getValueAsUChar8(emsData);
	printf("Unknown ems tag %08X -> %i.\n", emsData->tag, unknown);
	break;
    }
    protocol->destroyValueData(emsData);
}

int
handleResponseBatData(RscpProtocol * protocol,
		      SRscpValue * batteryData)
{
    uint8_t ucBatteryIndex = 0;
    // check each battery sub tag
    switch (batteryData->tag) {
    case TAG_BAT_INDEX:{
	ucBatteryIndex = protocol->getValueAsUChar8(batteryData);
	printf("Battery Index is %i\n", ucBatteryIndex);
	break;
    }
    case TAG_BAT_RSOC:{
	// response for TAG_BAT_REQ_RSOC
	float fSOC = protocol->getValueAsFloat32(batteryData);
	printf("Battery SOC is %0.1f %%\n", fSOC);
	break;
    }
    case TAG_BAT_MODULE_VOLTAGE:{
	// response for TAG_BAT_REQ_MODULE_VOLTAGE
	float fVoltage = protocol->getValueAsFloat32(batteryData);
	printf("Battery total voltage is %0.1f V\n",
	       fVoltage);
	break;
    }
    case TAG_BAT_CURRENT:{
	// response for TAG_BAT_REQ_CURRENT
	float fVoltage =
	    protocol->getValueAsFloat32(batteryData);
	printf("Battery current is %0.1f A\n", fVoltage);
	break;
    }
    case TAG_BAT_STATUS_CODE:{
	// response for TAG_BAT_REQ_STATUS_CODE
	uint32_t uiErrorCode =
	    protocol->getValueAsUInt32(batteryData);
	printf("Battery status code is 0x%08X\n",
	       uiErrorCode);
	break;
    }
    case TAG_BAT_ERROR_CODE:{
	// response for TAG_BAT_REQ_ERROR_CODE
	uint32_t uiErrorCode =
	    protocol->getValueAsUInt32(batteryData);
	printf("Battery error code is 0x%08X\n",
	       uiErrorCode);
	break;
    }
    default:
	uint8_t unknown =
    protocol->getValueAsUChar8(batteryData);
    printf("Unknown battery tag %08X -> %i\n", batteryData->tag, unknown);
    break;
    }
}


int handleResponseValue(RscpProtocol * protocol, SRscpValue * response,
			int *isAuthRequest)
{
    // check if any of the response has the error flag set and react accordingly
    if (response->dataType == RSCP::eTypeError) {
	// handle error for example access denied errors
	uint32_t uiErrorCode = protocol->getValueAsUInt32(response);
	printf("Tag 0x%08X received error code %u.\n",
	       response->tag, uiErrorCode);
	return -1;
    }
    // check the SRscpValue TAG to detect which response it is
    switch (response->tag) {
    case TAG_RSCP_AUTHENTICATION:{
	    // It is possible to check the response->dataType value to detect correct data type
	    // and call the correct function. If data type is known,
	    // the correct function can be called directly like in this case.
	    uint8_t ucAccessLevel = protocol->getValueAsUChar8(response);
	    if (ucAccessLevel > 0) {
		iAuthenticated = 1;
		*isAuthRequest = 1;
	    }
	    printf("RSCP authentitication level %i\n", ucAccessLevel);
	    break;
	}
    case TAG_EMS_POWER_PV:{
	    // response for TAG_EMS_REQ_POWER_PV
	    int32_t iPower = protocol->getValueAsInt32(response);
	    printf("EMS PV power is %i W\n", iPower);
	    break;
	}
    case TAG_EMS_POWER_BAT:{
	    // response for TAG_EMS_REQ_POWER_BAT
	    int32_t iPower = protocol->getValueAsInt32(response);
	    printf("EMS BAT power is %i W\n", iPower);
	    break;
	}
    case TAG_EMS_POWER_HOME:{
	    // response for TAG_EMS_REQ_POWER_HOME
	    int32_t iPower = protocol->getValueAsInt32(response);
	    printf("EMS house power is %i W\n", iPower);
	    break;
	}
    case TAG_EMS_POWER_GRID:{
	    // response for TAG_EMS_REQ_POWER_GRID
	    int32_t iPower = protocol->getValueAsInt32(response);
	    printf("EMS grid power is %i W\n", iPower);
	    break;
	}
    case TAG_EMS_POWER_ADD:{
	    // response for TAG_EMS_REQ_POWER_ADD
	    int32_t iPower = protocol->getValueAsInt32(response);
	    printf("EMS add power meter power is %i W\n", iPower);
	    break;
	}
    case TAG_BAT_DATA:{
	    // response for TAG_REQ_BAT_DATA
	    std::vector < SRscpValue > batteryData =
		protocol->getValueAsContainer(response);
	    for (size_t i = 0; i < batteryData.size(); ++i) {
		if (batteryData[i].dataType == RSCP::eTypeError) {
		    // handle error for example access denied errors
		    uint32_t uiErrorCode =
			protocol->getValueAsUInt32(&batteryData[i]);
		    printf("Tag 0x%08X received error code %u.\n",
			   batteryData[i].tag, uiErrorCode);
		    return -1;
		}
		handleResponseBatData(protocol, &batteryData[i]);
	    }
	    protocol->destroyValueData(batteryData);
	    break;
	}
    case TAG_EMS_GET_POWER_SETTINGS:{
	    // response for TAG_EMS_REQ_GET_POWER_SETTINGS
	    std::vector < SRscpValue > emsData =
		protocol->getValueAsContainer(response);
	    for (size_t i = 0; i < emsData.size(); ++i) {
		if (emsData[i].dataType == RSCP::eTypeError) {
		    // handle error for example access denied errors
		    uint32_t uiErrorCode =
			protocol->getValueAsUInt32(&emsData[i]);
		    printf("Tag 0x%08X received error code %u.\n",
			   emsData[i].tag, uiErrorCode);
		    return -1;
		}
		// check each ems power settings sub tag
		switch (emsData[i].tag) {
		case TAG_EMS_POWER_LIMITS_USED:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf("EMS power limits used is %i.\n",
			       weather_en);
			break;
		    }
		case TAG_EMS_MAX_CHARGE_POWER:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf("EMS max charge power is %i.\n",
			       weather_en);
			break;
		    }
		case TAG_EMS_MAX_DISCHARGE_POWER:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf("EMS max discharge power is %i.\n",
			       weather_en);
			break;
		    }
		case TAG_EMS_DISCHARGE_START_POWER:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf("EMS discharge start power is %i.\n",
			       weather_en);
			break;
		    }
		case TAG_EMS_POWERSAVE_ENABLED:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf("EMS powersave enabled is %i.\n",
			       weather_en);
			break;
		    }
		case TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf
			    ("EMS weather regulated charge enabled is %i.\n",
			     weather_en);
			break;
		    }
		case TAG_EMS_UNKNOWN:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf("EMS unknown is %i.\n", weather_en);
			break;
		    }
		    // ...
		default:
		    // default behaviour
		    printf("Unknown ems tag %08X\n", emsData[i].tag);
		    break;
		}
	    }
	    protocol->destroyValueData(emsData);
	    break;
	}
    case TAG_EMS_SET_POWER_SETTINGS:{
	    // resposne for TAG_EMS_REQ_SET_POWER_SETTINGS
	    std::vector < SRscpValue > emsData =
		protocol->getValueAsContainer(response);
	    for (size_t i = 0; i < emsData.size(); ++i) {
		if (emsData[i].dataType == RSCP::eTypeError) {
		    // handle error for example access denied errors
		    uint32_t uiErrorCode =
			protocol->getValueAsUInt32(&emsData[i]);
		    printf("Tag 0x%08X received error code %u.\n",
			   emsData[i].tag, uiErrorCode);
		    return -1;
		}
		// check each battery sub tag
		switch (emsData[i].tag) {
		case TAG_EMS_RES_WEATHER_REGULATED_CHARGE_ENABLED:{
			int8_t weather_en =
			    protocol->getValueAsInt32(&emsData[i]);
			printf
			    ("Weather regulated charge response: %i\n",
			     weather_en);
			break;
		    }
		default:
		    // default behaviour
		    printf("Unknown ems tag %08X\n", emsData[i].tag);
		    break;
		}
	    }
	    protocol->destroyValueData(emsData);
	    break;
	}
    case TAG_EMS_GET_IDLE_PERIODS:{
	    // resposne for TAG_EMS_REQ_GET_IDLE_PERIODS
	    std::vector < SRscpValue > emsData =
		protocol->getValueAsContainer(response);
	    idle_period_t periods[14];
	    for (size_t i = 0; i < emsData.size(); ++i) {
		if (emsData[i].dataType == RSCP::eTypeError) {
		    // handle error for example access denied errors
		    uint32_t uiErrorCode =
			protocol->getValueAsUInt32(&emsData[i]);
		    printf("Tag 0x%08X received error code %u.\n",
			   emsData[i].tag, uiErrorCode);
		    return -1;
		}
		handleResponseEMSGetIdlePeriods(protocol, &emsData[i], &periods[i]);
	    }
	    break;
	}
    default:
	// default behavior
	uint8_t unknown = protocol->getValueAsUChar8(response);
	printf("Unknown tag %08X -> %i.\n", response->tag, unknown);
	break;
    }
}

static int processReceiveBuffer(const unsigned char *ucBuffer,
				int iLength, int *isAuthRequest)
{
    RscpProtocol protocol;
    SRscpFrame frame;

    int iResult = protocol.parseFrame(ucBuffer, iLength, &frame);
    if (iResult < 0) {
	// check if frame length error occured
	// in that case the full frame length was not received yet
	// and the receive function must get more data
	if (iResult == RSCP::ERR_INVALID_FRAME_LENGTH) {
	    return 0;
	}
	// otherwise a not recoverable error occured and the connection can be closed
	else {
	    return iResult;
	}
    }

    int iProcessedBytes = iResult;

    // process each SRscpValue struct seperately
    for (unsigned int i; i < frame.data.size(); i++) {
	handleResponseValue(&protocol, &frame.data[i], isAuthRequest);
    }

    // destroy frame data and free memory
    protocol.destroyFrameData(frame);

    // returned processed amount of bytes
    return iProcessedBytes;
}

static void receiveLoop(bool & bStopExecution)
{
    //--------------------------------------------------------------------------------------------------------------
    // RSCP Receive Frame Block Data
    //--------------------------------------------------------------------------------------------------------------
    // setup a static dynamic buffer which is dynamically expanded (re-allocated) on demand
    // the data inside this buffer is not released when this function is left
    static int iReceivedBytes = 0;
    static std::vector < uint8_t > vecDynamicBuffer;
    int isAuthRequest = 0;

    // check how many RSCP frames are received, must be at least 1
    // multiple frames can only occur in this example if one or more frames are received with a big time delay
    // this should usually not occur but handling this is shown in this example
    int iReceivedRscpFrames = 0;
    while (!bStopExecution
	   && ((iReceivedBytes > 0) || iReceivedRscpFrames == 0)) {
	// check and expand buffer
	if ((vecDynamicBuffer.size() - iReceivedBytes) < 4096) {
	    // check maximum size
	    if (vecDynamicBuffer.size() > RSCP_MAX_FRAME_LENGTH) {
		// something went wrong and the size is more than possible by the RSCP protocol
		printf
		    ("Maximum buffer size exceeded %i\n",
		     vecDynamicBuffer.size());
		bStopExecution = true;
		break;
	    }
	    // increase buffer size by 4096 bytes each time the remaining size is smaller than 4096
	    vecDynamicBuffer.resize(vecDynamicBuffer.size() + 4096);
	}
	// receive data
	int iResult = SocketRecvData(iSocket,
				     &vecDynamicBuffer[0] + iReceivedBytes,
				     vecDynamicBuffer.size() -
				     iReceivedBytes);
	if (iResult < 0) {
	    // check errno for the error code to detect if this is a timeout or a socket error
	    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
		// receive timed out -> continue with re-sending the initial block
		printf("Response receive timeout (retry)\n");
		break;
	    }
	    // socket error -> check errno for failure code if needed
	    printf("Socket receive error. errno %i\n", errno);
	    bStopExecution = true;
	    break;
	} else if (iResult == 0) {
	    // connection was closed regularly by peer
	    // if this happens on startup each time the possible reason is
	    // wrong AES password or wrong network subnet (adapt hosts.allow file required)
	    printf("Connection closed by peer\n");
	    bStopExecution = true;
	    break;
	}
	// increment amount of received bytes
	iReceivedBytes += iResult;

	// process all received frames
	while (!bStopExecution) {
	    // round down to a multiple of AES_BLOCK_SIZE
	    int iLength = ROUNDDOWN(iReceivedBytes, AES_BLOCK_SIZE);
	    // if not even 32 bytes were received then the frame is still incomplete
	    if (iLength == 0) {
		break;
	    }
	    // resize temporary decryption buffer
	    std::vector < uint8_t > decryptionBuffer;
	    decryptionBuffer.resize(iLength);
	    // initialize encryption sequence IV value with value of previous block
	    aesDecrypter.SetIV(ucDecryptionIV, AES_BLOCK_SIZE);
	    // decrypt data from vecDynamicBuffer to temporary decryptionBuffer
	    aesDecrypter.Decrypt(&vecDynamicBuffer[0],
				 &decryptionBuffer[0],
				 iLength / AES_BLOCK_SIZE);

	    // data was received, check if we received all data
	    int iProcessedBytes =
		processReceiveBuffer(&decryptionBuffer[0],
				     iLength,
				     &isAuthRequest);
	    if (iProcessedBytes < 0) {
		// an error occured;
		printf("Error parsing RSCP frame: %i\n", iProcessedBytes);
		// stop execution as the data received is not RSCP data
		bStopExecution = true;
		break;

	    } else if (iProcessedBytes > 0) {
		// round up the processed bytes as iProcessedBytes does not include the zero padding bytes
		iProcessedBytes = ROUNDUP(iProcessedBytes, AES_BLOCK_SIZE);
		// store the IV value from encrypted buffer for next block decryption
		memcpy(ucDecryptionIV,
		       &vecDynamicBuffer[0] +
		       iProcessedBytes - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		// move the encrypted data behind the current frame data (if any received) to the front
		memcpy(&vecDynamicBuffer[0],
		       &vecDynamicBuffer[0] +
		       iProcessedBytes,
		       vecDynamicBuffer.size() - iProcessedBytes);
		// decrement the total received bytes by the amount of processed bytes
		iReceivedBytes -= iProcessedBytes;
		// increment a counter that a valid frame was received and
		// continue parsing process in case a 2nd valid frame is in the buffer as well
		iReceivedRscpFrames++;
		if (!isAuthRequest) {
		    printf
			("Successfully received %i RscpFrames\n",
			 iReceivedRscpFrames);
		    bStopExecution = true;
		}
	    } else {
		// iProcessedBytes is 0
		// not enough data of the next frame received, go back to receive mode if iReceivedRscpFrames == 0
		// or transmit mode if iReceivedRscpFrames > 0
		break;
	    }
	}
    }
}

static void mainLoop(int requests)
{
    RscpProtocol protocol;
    bool bStopExecution = false;

    while (!bStopExecution) {
	//--------------------------------------------------------------------------------------------------------------
	// RSCP Transmit Frame Block Data
	//--------------------------------------------------------------------------------------------------------------
	SRscpFrameBuffer frameBuffer;
	memset(&frameBuffer, 0, sizeof(frameBuffer));

	// create an RSCP frame with requests to some example data
	createRequest(&frameBuffer, requests);

	// check that frame data was created
	if (frameBuffer.dataLength > 0) {
	    // resize temporary encryption buffer to a multiple of AES_BLOCK_SIZE
	    std::vector < uint8_t > encryptionBuffer;
	    encryptionBuffer.resize(ROUNDUP
				    (frameBuffer.dataLength,
				     AES_BLOCK_SIZE));
	    // zero padding for data above the desired length
	    memset(&encryptionBuffer[0] +
		   frameBuffer.dataLength, 0,
		   encryptionBuffer.size() - frameBuffer.dataLength);
	    // copy desired data length
	    memcpy(&encryptionBuffer[0], frameBuffer.data,
		   frameBuffer.dataLength);
	    // set continues encryption IV
	    aesEncrypter.SetIV(ucEncryptionIV, AES_BLOCK_SIZE);
	    // start encryption from encryptionBuffer to encryptionBuffer, blocks = encryptionBuffer.size() / AES_BLOCK_SIZE
	    aesEncrypter.Encrypt(&encryptionBuffer[0],
				 &encryptionBuffer[0],
				 encryptionBuffer.size() / AES_BLOCK_SIZE);
	    // save new IV for next encryption block
	    memcpy(ucEncryptionIV,
		   &encryptionBuffer[0] +
		   encryptionBuffer.size() - AES_BLOCK_SIZE,
		   AES_BLOCK_SIZE);

	    // send data on socket
	    int iResult = SocketSendData(iSocket,
					 &encryptionBuffer[0],
					 encryptionBuffer.size());
	    if (iResult < 0) {
		printf("Socket send error %i. errno %i\n", iResult, errno);
		bStopExecution = true;
	    } else {
		// go into receive loop and wait for response
		receiveLoop(bStopExecution);
	    }
	}
	// free frame buffer memory
	protocol.destroyFrameData(&frameBuffer);

	// main loop sleep / cycle time before next request

	if (!bStopExecution)
	    sleep(1);
    }
}

int authLoop(e3dc_config_t *config)
{
    int auth_retry = MAX_AUTH_RETRY;

    RscpProtocol protocol;
    bool bStopExecution = false;
    while ((iAuthenticated != 1) && ((auth_retry + 1) > 0)
	   && !bStopExecution) {
	auth_retry--;
	//--------------------------------------------------------------------------------------------------------------
	// RSCP Transmit Frame Block Data
	//--------------------------------------------------------------------------------------------------------------
	SRscpFrameBuffer frameBuffer;
	memset(&frameBuffer, 0, sizeof(frameBuffer));

	// create an RSCP frame with requests to some example data
	createAuthRequest(&frameBuffer, config);

	// check that frame data was created
	if (frameBuffer.dataLength > 0) {
	    // resize temporary encryption buffer to a multiple of AES_BLOCK_SIZE
	    std::vector < uint8_t > encryptionBuffer;
	    encryptionBuffer.resize(ROUNDUP
				    (frameBuffer.dataLength,
				     AES_BLOCK_SIZE));
	    // zero padding for data above the desired length
	    memset(&encryptionBuffer[0] +
		   frameBuffer.dataLength, 0,
		   encryptionBuffer.size() - frameBuffer.dataLength);
	    // copy desired data length
	    memcpy(&encryptionBuffer[0], frameBuffer.data,
		   frameBuffer.dataLength);
	    // set continues encryption IV
	    aesEncrypter.SetIV(ucEncryptionIV, AES_BLOCK_SIZE);
	    // start encryption from encryptionBuffer to encryptionBuffer, blocks = encryptionBuffer.size() / AES_BLOCK_SIZE
	    aesEncrypter.Encrypt(&encryptionBuffer[0],
				 &encryptionBuffer[0],
				 encryptionBuffer.size() / AES_BLOCK_SIZE);
	    // save new IV for next encryption block
	    memcpy(ucEncryptionIV,
		   &encryptionBuffer[0] +
		   encryptionBuffer.size() - AES_BLOCK_SIZE,
		   AES_BLOCK_SIZE);

	    // send data on socket
	    int iResult = SocketSendData(iSocket,
					 &encryptionBuffer[0],
					 encryptionBuffer.size());
	    if (iResult < 0) {
		printf("Socket send error %i. errno %i\n", iResult, errno);
		bStopExecution = true;
		continue;
	    } else {
		// go into receive loop and wait for response
		receiveLoop(bStopExecution);
	    }
	}

	// auth loop sleep / cycle time before next request
	if (!iAuthenticated) {
	    printf("Authentication failed, retry...\n");
	    sleep(1);
	}
	// free frame buffer memory
	protocol.destroyFrameData(&frameBuffer);
    }

    if (!iAuthenticated)
	printf("Authentication failed due to timeout\n");

    return 0;
}

void showhelp(char *prog)
{
    printf("Usage:\n");
    printf("%s [-hebts] [-w 0|1]\n", prog);
    printf("  --help, -h         \tshows this help\n");
    printf("  --battery, -b      \tshows battery details\n");
    printf("  --ems, -e          \tshows ems details\n");
    printf("  --time, -t         \tshows idle periods\n");
    printf("  --settime, -s      \tsets idle periods (currently hardcoded values)\n");
    printf("  --weather, -w      \tsets weather enable option [on|off]\n");
}

int main(int argc, char *argv[])
{
    int iConnected = 0;
    int conn_retry = MAX_CONN_RETRY;
    int opt;
    int requests = 0;

    // get conf parameters
    FILE *fp = fopen(CONF_FILE, "r");
    char var[128], value[128], line[256];
    e3dc_config_t e3dc_config;
    if(fp) {
	while (fgets(line, sizeof(line), fp)) {
	    memset(var, 0, sizeof(var));
	    memset(value, 0, sizeof(value));
	    if(sscanf(line, "%[^ \t=]%*[\t ]=%*[\t ]%[^\n]", var, value) == 2) {
		if(strcmp(var, "server_ip") == 0)
		    strcpy(e3dc_config.server_ip, value);
		else if(strcmp(var, "server_port") == 0)
		    e3dc_config.server_port = atoi(value);
		else if(strcmp(var, "e3dc_user") == 0)
		    strcpy(e3dc_config.e3dc_user, value);
		else if(strcmp(var, "e3dc_password") == 0)
		    strcpy(e3dc_config.e3dc_password, value);
		else if(strcmp(var, "aes_password") == 0)
		    strcpy(e3dc_config.aes_password, value);
	    }
	}
	fclose(fp);
    }

    // get commandline parameters
    while (1) {
	static struct option long_options[] = {
	    {"help",		no_argument,		0, 'h'},
	    {"battery",		no_argument,		0, 'b'},
	    {"ems",		no_argument,		0, 'e'},
	    {"time",		no_argument,		0, 't'},
	    {"settime",		no_argument,		0, 's'},
	    {"weather",		required_argument,	0, 'w' },
	};
	int option_index = 0;
	opt = getopt_long(argc, argv, "hbetsw:", long_options, &option_index);

	if(opt == -1)
	    break;

	switch (opt){
	case 'h': {
	    showhelp(argv[0]);
	    return 0;
	    break;
	    }
	case 'b': {
	    requests |= TAG_BATTERY;
	    break;
	    }
	case 'e': {
	    requests |= TAG_EMS;
	    break;
	    }
	case 't': {
	    requests |= TAG_GET_IDLE_PERIODS;
	    break;
	    }
	case 's': {
	    requests |= TAG_SET_IDLE_PERIODS;
	    break;
	    }
	case 'w': {
	    requests |= TAG_WEATHER_ENABLE;
	    if (atoi(optarg) == 1)
		requests |= TAG_WEATHER_ENABLE_F;
	    else if (atoi(optarg) == 0)
		requests &= ~TAG_WEATHER_ENABLE_F;
	    else
		requests &= ~TAG_WEATHER_ENABLE;
	    break;
	    }
	default:
	    printf("%s: option '-%c' is invalid: ignored\n", argv[0], optopt);
	    break;
	}
    }

    if(requests & TAG_BATTERY)
	printf("Get battery details\n");
    if(requests & TAG_EMS)
	printf("Get ems details\n");
    if(requests & TAG_GET_IDLE_PERIODS)
	printf("Get idle periods details\n");
    if(requests & TAG_SET_IDLE_PERIODS)
	printf("Set idle periods details\n");
    if(requests & TAG_WEATHER_ENABLE)
	printf("Set weather enable option\n");

    // connect to server
    while (!iConnected && (conn_retry + 1) > 0) {
	printf("Connecting to server %s:%i\n", e3dc_config.server_ip, e3dc_config.server_port);
	iSocket = SocketConnect(e3dc_config.server_ip, e3dc_config.server_port);
	if (iSocket < 0) {
	    printf("Connection failed\n");
	    sleep(1);
	    conn_retry--;
	    continue;
	}
	iConnected = 1;
	printf("Connection success\n");

    }
    if (!iConnected) {
	printf("Connection failed due to timeout\n");
	return -1;
    }
    // create AES key and set AES parameters
    {
	// initialize AES encryptor and decryptor IV
	memset(ucDecryptionIV, 0xff, AES_BLOCK_SIZE);
	memset(ucEncryptionIV, 0xff, AES_BLOCK_SIZE);

	// limit password length to AES_KEY_SIZE
	int iPasswordLength = strlen(e3dc_config.aes_password);
	if (iPasswordLength > AES_KEY_SIZE)
	    iPasswordLength = AES_KEY_SIZE;

	// copy up to 32 bytes of AES key password
	uint8_t ucAesKey[AES_KEY_SIZE];
	memset(ucAesKey, 0xff, AES_KEY_SIZE);
	memcpy(ucAesKey, e3dc_config.aes_password, iPasswordLength);

	// set encryptor and decryptor parameters
	aesDecrypter.SetParameters(AES_KEY_SIZE * 8, AES_BLOCK_SIZE * 8);
	aesEncrypter.SetParameters(AES_KEY_SIZE * 8, AES_BLOCK_SIZE * 8);
	aesDecrypter.StartDecryption(ucAesKey);
	aesEncrypter.StartEncryption(ucAesKey);
    }

    authLoop(&e3dc_config);
    if (iAuthenticated) {
	printf("Authentication success\n");
	// enter the main transmit / receive loop
	mainLoop(requests);
    } else {
	printf("Authentication failed\n");
	// close socket connection
	SocketClose(iSocket);
	iSocket = -1;
	return -1;
    }

    // close socket connection
    SocketClose(iSocket);
    iSocket = -1;

    return 0;
}
