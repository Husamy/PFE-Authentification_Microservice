from rest_framework import serializers
from .models import CustomUser , organisation , Requestjoin , Invitation, keys
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken



class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email/password")

        refresh = RefreshToken.for_user(user)

        # Customize the token with additional claims
        refresh['user_id'] = user.id
        refresh['email'] = user.email

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        
        

class CustomUserSerializer(serializers.ModelSerializer):
    isAdmin = serializers.ReadOnlyField()
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'isAdmin', 'last_name', 'organisation', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['organisation'] = None  # set 'organisation' to None
        user = CustomUser.objects.create_user(**validated_data)
        return user

class CustomUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields =  ['first_name', 'last_name', 'organisation', 'password']  
class OrganisationSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.email')
    class Meta:
        model = organisation
        fields = ('id', 'name', 'description', 'members', 'owner', 'country_name', 'state_or_province_name', 'locality_name',)

    def create(self, validated_data):
        validated_data['owner'] = self.context['request'].user
        return super().create(validated_data)
    
    def get_queryset(self):
        return organisation.objects.filter(owner=self.request.user)
    
    
class RequestjoinSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Requestjoin
        fields = ('id', 'request_status', 'message', 'organisation', 'created_at')

    def create(self, validated_data):
        validated_data['requested_by'] = self.context['request'].user
        return super().create(validated_data)
   
    def to_representation(self, instance):
        if hasattr(self.context, 'request'):
            if self.context['request'].method == 'GET':
                self.fields['requested_by'] = serializers.CharField()
            elif self.context['request'].method == 'DELETE':
                pass
            else:
                self.fields.pop('requested_by', None)
        
        return super().to_representation(instance)


class keysSerializer(serializers.ModelSerializer):
    privateKey = serializers.ReadOnlyField()
    publicKey = serializers.ReadOnlyField()
    user_id = serializers.ReadOnlyField(source='user_id.id')

    class Meta:
        model = keys
        fields = ('privateKey', 'publicKey', 'user_id')
    
    def get_queryset(self):
        return keys.objects.filter(user_id=self.request.user)


class OrganisationMemberSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()

    class Meta:
        model = CustomUser
        fields = ('id','first_name', 'last_name', 'email')


class RequestUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Requestjoin
        fields = ['request_status']

class InvitationUpdateSerializer(serializers.ModelSerializer):    
    class Meta:
        model = Invitation
        fields = ['request_status']

class InvitationjoinSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Invitation
        fields = ('id','request_status','guest','created_at')
        
    def create(self, validated_data):
        validated_data['organisation'] = self.context['request'].user.organisation
        return super().create(validated_data)
    
    def to_representation(self, instance):
        if self.context['request'].method == 'GET':
            self.fields['organisation'] = serializers.CharField()
        else:
            self.fields.pop('organisation', None)
        
        return super().to_representation(instance)
    