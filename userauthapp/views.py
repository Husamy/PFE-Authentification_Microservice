from django.shortcuts import render

# Create your views here.
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render
from rest_framework import generics 
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin ,CreateModelMixin
from .models import CustomUser , organisation , Requestjoin , Invitation
from .serializers import CustomUserSerializer ,OrganisationMemberSerializer,InvitationUpdateSerializer,OrganisationSerializer , InvitationjoinSerializer , RequestjoinSerializer , RequestUpdateSerializer
from rest_framework import status
from rest_framework.response import Response
from .serializers import UserLoginSerializer
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import logout
from rest_framework.authentication import TokenAuthentication
import requests
from rest_framework import permissions
import os
from django.shortcuts import get_object_or_404
from rest_framework.generics import GenericAPIView,  UpdateAPIView

class IsOwner(permissions.BasePermission):
  
    def has_object_permission(self, request, view, obj):
        # Check if the authenticated user is the owner of the organization
        return obj.organisation.owner == request.user

class IsGuest(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        
        return obj.guest == request.user

class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        response_data = serializer.validated_data


        host_ip = os.environ.get('HOST_IP')
        action = 'login'
        email = request.data['email']
        timestamp_data = {'action': action, 'email': email}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/create/'
        response = requests.post(timestamp_url, data=timestamp_data)
        return Response(response_data, status=status.HTTP_200_OK)







class UserLogoutView(generics.GenericAPIView):
    def post(self, request, *args, **kwargs):
        try:
            request.user.auth_token.delete()
            logout(request)
        except (AttributeError, ObjectDoesNotExist):
            pass
        return Response({'message': 'Successfully logged out.'})









class CustomUserApi(generics.GenericAPIView, CreateModelMixin, ListModelMixin):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request):
        # Create a new user account
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Send the user ID and email address to the timestamp microservice
        host_ip = os.environ.get('HOST_IP')
        action = 'User Created'
        email = serializer.data['email']
        timestamp_data = {'action': action, 'email': email}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/create/'
        response = requests.post(timestamp_url, data=timestamp_data)

        # Return a JSON response indicating success
        return Response(serializer.data, status=201)







class PersonalUserAPI(generics.GenericAPIView, RetrieveModelMixin):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)


class CustomUserUpdateApi(generics.UpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'email'

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())

        # Get the email from the request data
        email = self.request.data.get('email')

        # Lookup the object based on email
        obj = get_object_or_404(queryset, email=email)
        self.check_object_permissions(self.request, obj)
        return obj

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.organisation = request.data.get('organisation')
        instance.save()

        serializer = self.get_serializer(instance)
        return Response(serializer.data)



# Invitation Views : 
class InvitationDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Invitation.objects.all()
    serializer_class = InvitationjoinSerializer
    permission_classes = [IsOwner]
    ''' action = 'Invitation Deleted'
    host_ip = os.environ.get('HOST_IP')
    timestamp_data = {'action': action, 'owner': , 'organisation': organisation.name}
    timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg'
    response = requests.post(timestamp_url, data=timestamp_data)'''

class InvitaionUpdate(generics.RetrieveUpdateAPIView):
    queryset = Invitation.objects.all()
    serializer_class = InvitationUpdateSerializer
    permission_classes = [permissions.IsAuthenticated, IsGuest]
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)

        # Perform custom logic here
        if serializer.validated_data.get('request_status') == 'Accepted':
            custom_user = instance.guest
            organisation = instance.organisation
            custom_user.organisation = organisation
            custom_user.save()
            # Update the membres field in organisation model ( add user_id to membres )
            organisation.members.append(custom_user.id)
            organisation.save()

            # Update the request_status field in Requestjoin model
            instance.request_status = serializer.validated_data.get('request_status')
            instance.save()


            action = 'Request Accepted'
            host_ip = os.environ.get('HOST_IP')
            timestamp_data = {'action': action, 'owner': custom_user.email, 'organisation': organisation.name}
            timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg'
            response = requests.post(timestamp_url, data=timestamp_data)

            # Update the organisation field in CustomUser model
            
            
            return Response(status=status.HTTP_200_OK)

        elif serializer.validated_data.get('request_status') == 'Rejected':
            instance.request_status = serializer.validated_data.get('request_status')
            instance.save()
            action = 'Request Rejected'
            host_ip = os.environ.get('HOST_IP')
            timestamp_data = {'action': action, 'owner': custom_user.email, 'organisation': organisation.name}
            timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg/'
            response = requests.post(timestamp_url, data=timestamp_data)

            return Response(status=status.HTTP_200_OK)

        else:
            return Response({'request_status': 'Request status must be either Rejected or Accepted'}, status=status.HTTP_400_BAD_REQUEST)

        

class InvitationJoin(generics.ListCreateAPIView):
    serializer_class = InvitationjoinSerializer

    def get_queryset(self):
        user = self.request.user
        organisation = user.organisation

        if organisation is None:
                return Invitation.objects.filter(guest=user)
        elif organisation.is_owner(user):
                return Invitation.objects.filter(organisation=organisation)
        else:
                return Invitation.objects.filter(guest=user)

    def perform_create(self, serializer):
        org = self.request.user.organisation
        guest = serializer.validated_data['guest']
        if guest.organisation :
            return Response({'error': 'User already belongs to an organization'}, status=status.HTTP_400_BAD_REQUEST)        
        serializer.save(organisation=org)
        # Send a timestamp to the organisation service
        host_ip = os.environ.get('HOST_IP')
        action = 'Invitation Send'
        timestamp_data = {'action': action, 'owner': str(self.request.user.email), 'organisation': org.name}
        timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class RequestJoin(generics.ListCreateAPIView):
    serializer_class = RequestjoinSerializer
    queryset = Requestjoin.objects.all()

    def get_queryset(self):
        user = self.request.user
        organisation = user.organisation

        if organisation is None:
                return Requestjoin.objects.filter(requested_by=user)
        elif organisation.is_owner(user):
            # Return all requests belonging to the organisation
            return Requestjoin.objects.filter(organisation=organisation)
        else:
            # Return only requests made by the user
            return Requestjoin.objects.filter(requested_by=user)

    def post(self, request, *args, **kwargs):
        requested_by = request.user
        custom_user = CustomUser.objects.get(email=requested_by)
        if custom_user.organisation:
            return Response({'error': 'User already belongs to an organization'}, status=status.HTTP_400_BAD_REQUEST)

        organisation_name = request.data['organisation']
        org = organisation.objects.get(name=organisation_name)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request_join = serializer.save(requested_by=requested_by, organisation=org)
        # Send a timestamp to the organisation service
        host_ip = os.environ.get('HOST_IP')
        action = 'Request Join'
        timestamp_data = {'action': action, 'owner': str(requested_by), 'organisation': organisation_name}
        timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class OrganisationMembersView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OrganisationMemberSerializer

    def get_queryset(self):
        # Get the organisation object where the owner is the logged in user
        org = organisation.objects.get(owner=self.request.user)

        # Get the list of member IDs for the organisation
        member_ids = org.members

        # Get the first name, last name, and email of members using the IDs
        members = CustomUser.objects.filter(id__in=member_ids).values('first_name', 'last_name', 'email')

        return members

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)
    
class OrganisationDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = organisation.objects.all()
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated, IsOwner]

class Organisation(generics.ListCreateAPIView):
    queryset = organisation.objects.all()
    serializer_class = OrganisationSerializer

    def perform_create(self, serializer):
        # Check if user already belongs to an organization
        custom_user = self.request.user
        if custom_user.organisation:
            return Response({'error': 'User already belongs to an organization'}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        # Update User Model (admin)
        organisation = serializer.instance
        custom_user.organisation = organisation
        custom_user.save()

        # Send Request to Timestamp MicroService
        action = 'Organisation Created'
        host_ip = os.environ.get('HOST_IP')
        timestamp_data = {'action': action, 'owner': custom_user.email, 'organisation': serializer.instance.name}
        timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data)

    def get_queryset(self):
        return organisation.objects.filter(owner=self.request.user)


class RequestUpdate(generics.RetrieveUpdateAPIView):
    queryset = Requestjoin.objects.all()
    serializer_class = RequestUpdateSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)

        # Perform custom logic here
        if serializer.validated_data.get('request_status') == 'Accepted':
            custom_user = instance.requested_by
            organisation = instance.organisation
            custom_user.organisation = organisation
            custom_user.save()
            # Update the membres field in organisation model ( add user_id to membres )
            organisation.members.append(custom_user.id)
            organisation.save()

            # Update the request_status in request model 
            # Update the request_status field in Requestjoin model
            instance.request_status = serializer.validated_data.get('request_status')
            instance.save()


            action = 'Request Accepted'
            host_ip = os.environ.get('HOST_IP')
            timestamp_data = {'action': action, 'owner': custom_user.email, 'organisation': organisation.name}
            timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg'
            response = requests.post(timestamp_url, data=timestamp_data)

            # Update the organisation field in CustomUser model
            
            
            return Response(status=status.HTTP_200_OK)

        elif serializer.validated_data.get('request_status') == 'Rejected':
            instance.request_status = serializer.validated_data.get('request_status')
            instance.save()
            action = 'Request Rejected'
            host_ip = os.environ.get('HOST_IP')
            timestamp_data = {'action': action, 'owner': custom_user.email, 'organisation': organisation.name}
            timestamp_url = 'http://' + str(host_ip) + ':8001/api/createorg'
            response = requests.post(timestamp_url, data=timestamp_data)

            return Response(status=status.HTTP_200_OK)

        else:
            return Response({'request_status': 'Request status must be either Rejected or Accepted'}, status=status.HTTP_400_BAD_REQUEST)

        


class RequestDestroy(generics.RetrieveDestroyAPIView):
    queryset = Requestjoin.objects.all()
    serializer_class = RequestjoinSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        # Serialize instance and print the data
        serialized_data = self.serializer_class(instance).data
        
        action = 'Request Deleted'
        host_ip = os.environ.get('HOST_IP')
        timestamp_data = {'action': action, 'owner': serialized_data['user'], 'organisation_id': serialized_data['organisation_id']}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg'
        response = requests.post(timestamp_url, data=timestamp_data)

        self.perform_destroy(instance)

        return Response(status=status.HTTP_204_NO_CONTENT)
    

