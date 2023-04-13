from django.urls import path
from .views import CustomUserApi, PersonalUserAPI
from .views import UserLoginView, UserLogoutView ,InvitaionUpdate,InvitationDetail,OrganisationMembersView, OrganisationDetail, InvitationJoin ,CustomUserUpdateApi , RequestJoin , Organisation  , RequestUpdate , RequestDestroy 


urlpatterns = [
    path('users/<int:pk>', PersonalUserAPI.as_view()),
    path('users/', CustomUserApi.as_view()),
    path('login/', UserLoginView.as_view()),
    path('logout/', UserLogoutView.as_view()),
    path('update/', CustomUserUpdateApi.as_view(), name='user_update'),
    # Organisation Urls 
    path('organisation/create/', Organisation.as_view()),
    path('organisation/delete/<int:pk>', OrganisationDetail.as_view()),
    path('organisation/users/',OrganisationMembersView.as_view()),
    # Request Urls 
    path('request/create/', RequestJoin.as_view()),
    path('request/update/<int:pk>/',RequestUpdate.as_view()),
    path('request/delete/<int:pk>/',RequestDestroy.as_view()),
    # Invitaiton Urls 
    path('invitation/create/',InvitationJoin.as_view()),
    path('invitation/update/<int:pk>/',InvitaionUpdate.as_view()),
    path('invitation/delete/<int:pk>/',InvitationDetail.as_view()),

]