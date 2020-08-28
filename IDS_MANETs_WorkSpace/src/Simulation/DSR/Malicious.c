/************************************************************************************
* Copyright (C) 2015                                                               *
* TETCOS, Bangalore. India                                                         *
*                                                                                  *
* Tetcos owns the intellectual property rights in the Product and its content.     *
* The copying, redistribution, reselling or publication of any or all of the       *
* Product or its content without express prior written consent of Tetcos is        *
* prohibited. Ownership and / or any other right relating to the software and all  *
* intellectual property rights therein shall remain at all times with Tetcos.      *
*                                                                                  *
* Author:    Shashi Kant Suman                                                     *
*                                                                                  *
* ---------------------------------------------------------------------------------*/

/****************************************************
         This file contains code for generation of Malicious Node(SinkHole) for networks running DSR in Layer3.
		 This works only for UDP and not for TCP.
		 
		 
		 The function fn_NetSim_DSR_MaliciousNode(NetSim_EVENTDETAILS*) 
		 return 1 when the deviceID is the malicious node which is mentioned in the if statement in the function definition.

		 
		 The function fn_NetSim_DSR_MaliciousRouteAddToCache(NetSim_EVENTDETAILS*)
		 adds the target address of the DSR RREQ it receives to its route cache so as to create a false route from 
		 the Source node to target node


		 The function fn_NetSim_DSR_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS*)
		 Process the Data Packet received by the Malicious Node. It does not call the NetworkOut Event and destroys 
		 the packet, thus giving false acknowledge replies.

		 Code Flow - 
		 If The Node is a Malicious Node, Then when a Route Request is Received, the Function adds the route from itself 
		 to the target in the route cache and sends a false route reply.
		 When a malicious node receives a data packet, it gives acknowledge reply and frees the packet.
		  
		 


*****************************************************/


	/* Malicious Node */


#include "main.h"
#include "DSR.h"
#include "List.h"
#define array_size(_arr) (sizeof(_arr)/sizeof(_arr[0]))

bool fn_NetSim_DSR_MaliciousNode(NETSIM_ID,double);
int fn_NetSim_DSR_MaliciousRouteAddToCache(NetSim_EVENTDETAILS*);
int fn_NetSim_DSR_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS*);



typedef struct stru_malicious_node
{
	NETSIM_ID id; //Malicious node id
	double time; //In microsec. Time at which node become malicious
}MALICIOUS_NODE,*PMALICIOUS_NODE;

/* format	{	{2,0},
*				{5,1000000},
*				{8,900}
*			};
*/
MALICIOUS_NODE malicious_node[] = { {2,500000} }; //Example:Node 2 is malicious node after time 0 sec.
	

bool fn_NetSim_DSR_MaliciousNode(NETSIM_ID dev,double time)
{
	int i;
	#ifdef _IDS_
	#ifdef _IDS_METRIC_INIT
	int n;
	//mal_dev_count=(sizeof(malicious_node)/(sizeof(unsigned short int)+sizeof(double)));
	mal_dev_count=sizeof(malicious_node)/16;
	
	for(n=0;n<mal_dev_count;n++)
	{
	mal_devid[n]=malicious_node[n].id;
	mal_start_time[n]=malicious_node[n].time;
	
	}
	#undef _IDS_METRIC_INIT
	#endif
	#endif
	
	for(i=0;i<array_size(malicious_node);i++)
	{
		if(dev == malicious_node[i].id && time >= malicious_node[i].time)
		{
			return true;
		}
	}
	return false;
}




int fn_NetSim_DSR_MaliciousRouteAddToCache(NetSim_EVENTDETAILS* pstruEventDetails)
{
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	DSR_OPTION_HEADER* option = packet->pstruNetworkData->Packet_RoutingProtocol;
	DSR_RREQ_OPTION* rreq = option->options;

		NETSIM_IPAddress IP_Dev2 = dsr_get_dev_ip(pstruEventDetails->nDeviceId);
		NETSIM_IPAddress IP_Target2 = rreq->targetAddress;
		double dTime = pstruEventDetails->dEventTime;
		
			DSR_DEVICE_VAR* devVar2 = DSR_DEV_VAR(pstruEventDetails->nDeviceId);
			DSR_ROUTE_CACHE* cache2 = ROUTECACHE_ALLOC();
			cache2->nLength = 2;
			cache2->dTimeOutTime = dTime+ROUTE_CACHE_TIMEOUT;
			cache2->address = calloc(cache2->nLength,sizeof* cache2->address);
			cache2->address[0] = IP_COPY(IP_Dev2);
			cache2->address[1] = IP_COPY(IP_Target2);
			LIST_ADD_LAST(&devVar2->pstruRouteCache,cache2);
	
	return 1;

}

int fn_NetSim_DSR_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS* pstruEventDetails)
{
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	DSR_OPTION_HEADER* option;
	DSR_SOURCE_ROUTE_OPTION* srcRouteOption;
	option = packet->pstruNetworkData->Packet_RoutingProtocol;
	if(option->ackRequestOption)
		DSR_PROCESS_ACK_REQUEST(packet);
	if(option && option->optType == optType_SourceRoute)
	{
		//update the metrics
		DSR_DEV_VAR(pstruEventDetails->nDeviceId)->dsrMetrics.packetReceived++;
		srcRouteOption = option->options;
		
		if(srcRouteOption->nSegsLeft==0)
		{
			//Add Transport in event
			pstruEventDetails->nEventType = TRANSPORT_IN_EVENT;
			fnpAddEvent(pstruEventDetails);
			return 1;
		}
		srcRouteOption->nSegsLeft -=1;
		fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
		/*
		//Add network out event
		pstruEventDetails->nEventType = NETWORK_OUT_EVENT;
		fnpAddEvent(pstruEventDetails);
		*/
		return 1;
	}
	fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
	return 0;
}
