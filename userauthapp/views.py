from django.shortcuts import render

# Create your views here.
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render
from rest_framework import generics 
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin ,CreateModelMixin
from .models import CustomUser , organisation , Requestjoin , Invitation, keys
from .serializers import CustomUserSerializer, OrganisationMemberSerializer,CustomUserUpdateSerializer , InvitationUpdateSerializer,OrganisationSerializer , InvitationjoinSerializer , RequestjoinSerializer , RequestUpdateSerializer, keysSerializer
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
from rest_framework import generics, status
from rest_framework.response import Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from django.shortcuts import get_object_or_404
from django.core import serializers




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

    def get_object(self):
        return CustomUser.objects.filter(id=self.request.user.id)

    def get(self, request, *args, **kwargs):
        queryset = self.get_object()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request):
        # Create a new user account
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        publicKey = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        privateKey = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        keys_obj = keys.objects.create(user_id=user , privateKey=privateKey, publicKey=publicKey)
        

        # Send the user ID and email address to the timestamp microservice
       

        # Return a JSON response indicating success
        return Response(serializer.data, status=201)


class keysAPI(generics.ListAPIView):
    queryset = keys.objects.all()
    serializer_class = keysSerializer
    permission_classes=[IsAuthenticated,]

    




class PersonalUserAPI(generics.GenericAPIView, RetrieveModelMixin):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)


class CustomUserUpdateApi(generics.UpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserUpdateSerializer
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
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()



# Invitation Views : 
class InvitationDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Invitation.objects.all()
    serializer_class = InvitationjoinSerializer
    permission_classes = [IsOwner]
    
    

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        action = 'Invitation Deleted'
        host_ip = os.environ.get('HOST_IP')
        token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        headers = {'Authorization': f'Bearer {token}'}
        timestamp_data = {'action': action, organisation: instance.organisation.name}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data, headers=headers)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
    

class InvitaionUpdate(generics.RetrieveUpdateDestroyAPIView):
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
            token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
            headers = {'Authorization': f'Bearer {token}'}
            timestamp_data = {'action': action, organisation: instance.organisation.name}
            timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
            response = requests.post(timestamp_url, data=timestamp_data, headers=headers)

            # Update the organisation field in CustomUser model
            
            
            return Response(status=status.HTTP_200_OK)

        elif serializer.validated_data.get('request_status') == 'Rejected':
            instance.request_status = serializer.validated_data.get('request_status')
            instance.save()
            action = 'Request Rejected'
            host_ip = os.environ.get('HOST_IP')
            token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
            headers = {'Authorization': f'Bearer {token}'}
            timestamp_data = {'action': action, organisation: instance.organisation.name}
            timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
            response = requests.post(timestamp_url, data=timestamp_data, headers=headers)

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
        token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        headers = {'Authorization': f'Bearer {token}'}
        timestamp_data = {'action': action, organisation: org.name}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data, headers=headers)
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
        token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        headers = {'Authorization': f'Bearer {token}'}
        timestamp_data = {'action': action, organisation: organisation.name}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data, headers=headers)
        response = requests.post(timestamp_url, data=timestamp_data)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class OrganisationMembersView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OrganisationMemberSerializer

    def get_queryset(self):
        # Get the organisation object where the owner is the logged in user
        user_id = self.request.user.id
        print(self.request.user.id)
        user =  CustomUser.objects.get(id=user_id)
        print(user)
        print('hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh')
        org = user.organisation

        # Get the list of member IDs for the organisation
        member_ids = org.members

        # Get the first name, last name, and email of members using the IDs
        members = CustomUser.objects.filter(id__in=member_ids).values('id','first_name', 'last_name', 'email')

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

        # Set the member field to a list containing the id of the requesting user
        serializer.validated_data['members'] = [custom_user.id]
        
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
        auth_header = self.request.headers.get("Authorization")
        token = auth_header.split(" ")[1]
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(timestamp_url, data=timestamp_data,headers=headers)
    
    def get_queryset(self):
        user_id = self.request.user.id
        print(self.request.user.id)
        user =  CustomUser.objects.get(id=user_id)
        print(user)
        print('hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh')
        org = user.organisation
        return organisation.objects.filter(name=org)


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
            token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
            headers = {'Authorization': f'Bearer {token}'}
            timestamp_data = {'action': action, organisation: organisation.name}
            timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
            response = requests.post(timestamp_url, data=timestamp_data, headers=headers)

            # Update the organisation field in CustomUser model
            
            
            return Response(status=status.HTTP_200_OK)

        elif serializer.validated_data.get('request_status') == 'Rejected':
            instance.request_status = serializer.validated_data.get('request_status')
            instance.save()
            action = 'Request Rejected'
            host_ip = os.environ.get('HOST_IP')
            token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
            headers = {'Authorization': f'Bearer {token}'}
            timestamp_data = {'action': action, organisation: organisation.name}
            timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
            response = requests.post(timestamp_url, data=timestamp_data, headers=headers)

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
        token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        headers = {'Authorization': f'Bearer {token}'}
        timestamp_data = {'action': action, organisation: instance.organisation.name}
        timestamp_url = 'http://'+str(host_ip)+':8001/api/createorg/'
        response = requests.post(timestamp_url, data=timestamp_data, headers=headers)

        self.perform_destroy(instance)

        return Response(status=status.HTTP_204_NO_CONTENT)
    

